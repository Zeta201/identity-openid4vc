/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.verification.handlers;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.internal.VerificationServiceComponentHolder;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.CredentialSignatureValidator;
import org.wso2.carbon.identity.sdjwt.Disclosure;
import org.wso2.carbon.identity.sdjwt.SDJWT;
import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifier for {@code dc+sd-jwt} credential presentations.
 *
 * <p>Owns all SD-JWT-specific logic end-to-end: token parsing, issuer signature
 * validation, disclosure verification, expiry, KB-JWT holder binding, vct type
 * enforcement, technical claim stripping, and metadata extraction.
 *
 * <p>Each token component is parsed exactly once:
 * <ul>
 *   <li>{@link SDJWT#parse} — once at the top of {@link #verify}</li>
 *   <li>{@link SignedJWT#parse} for the issuer JWT — once, result threaded through</li>
 *   <li>{@link SignedJWT#parse} for the KB-JWT — once inside
 *       {@link #verifyKeyBinding}, returned and reused for metadata</li>
 * </ul>
 *
 * <p>KB-JWT validation enforces:
 * <ul>
 *   <li>Signature verified against the holder key in the {@code cnf} claim.</li>
 *   <li>{@code nonce} verified against the expected nonce from the VP request.</li>
 *   <li>{@code iat} freshness verified (within 5-minute window).</li>
 *   <li>{@code sd_hash} verified against a fresh hash of the presentation string.</li>
 *   <li>{@code typ} header verified to be {@code kb+jwt}.</li>
 * </ul>
 */
public class SdJwtVerifier implements Verifier {

    private static final Log LOG = LogFactory.getLog(SdJwtVerifier.class);

    private static final String KB_JWT_TYPE = "kb+jwt";
    private static final String CNF_JWK_CLAIM = "jwk";
    private static final String KB_JWT_SD_HASH_CLAIM = "sd_hash";
    private static final String KB_JWT_NONCE_CLAIM = "nonce";
    private static final long KB_JWT_IAT_TOLERANCE_MS = 5 * 60 * 1000L;

    /** JWT/SD-JWT protocol-level fields excluded from the subject-attribute claims map. */
    private static final Set<String> PROTOCOL_CLAIMS = new HashSet<>(Arrays.asList(
            VPConstants.JWTClaims.ISS, VPConstants.JWTClaims.SUB,
            VPConstants.JWTClaims.IAT, VPConstants.JWTClaims.EXP,
            VPConstants.JWTClaims.JTI, VPConstants.JWTClaims.NBF,
            VPConstants.JWTClaims.AUD,
            SDJWTConstants.CLAIM_CNF, SDJWTConstants.CLAIM_SD, SDJWTConstants.CLAIM_SD_ALG,
            SDJWTConstants.CLAIM_VCT
    ));

    @Override
    public String getFormat() {

        return Constants.VC_SD_JWT_FORMAT;
    }

    @Override
    public PresentationMetadata verify(CredentialVerificationContext ctx) throws VerificationException {

        // Step 1: Parse the full SD-JWT presentation. The wire format is:
        //   <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~[<KB-JWT>]
        // Each segment is tilde-separated; the KB-JWT is present for holder binding.
        SDJWT sdJwt;
        try {
            sdJwt = SDJWT.parse(ctx.getCredentialToken());
        } catch (SDJWTException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse SD-JWT: " + e.getMessage(), e);
        }

        // Step 2: Parse the issuer-signed JWT and verify the issuer signature. The SDJWT library
        // only holds the raw string, so we parse once here and reuse the object throughout.
        SignedJWT issuerJwt;
        try {
            issuerJwt = SignedJWT.parse(sdJwt.getIssuerSignedJwt());
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse issuer-signed JWT: " + e.getMessage(), e);
        }
        validateSignature(ctx.getRequestedCredential(), issuerJwt);

        // Step 3: Extract the claims set from the already-parsed issuer JWT.
        JWTClaimsSet claimsSet;
        try {
            claimsSet = issuerJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to read claims from issuer-signed JWT: " + e.getMessage(), e);
        }

        // Step 4: Check credential expiry before processing disclosures to fail fast.
        verifyExpiration(claimsSet);

        // Step 5: Verify each disclosure's hash against the _sd array in the issuer-signed JWT
        // and merge the revealed claim values into the working claims map.
        Map<String, Object> claims = extractAndApplyDisclosures(claimsSet, sdJwt.getDisclosures());

        // Step 6: Verify KB-JWT holder binding. Returns the parsed KB-JWT for reuse in metadata
        // so it is not re-parsed a second time.
        SignedJWT kbJwt = verifyKeyBinding(sdJwt, claimsSet, ctx.getExpectedNonce(), ctx.getExpectedAudience());

        // Step 7: Enforce the expected vct (credential type) from the presentation definition.
        enforceVctType(ctx.getRequestedCredential(), claims);

        // Strip JWT/SD-JWT technical fields (iss, sub, iat, exp, cnf, _sd, vct, etc.)
        // before returning — the caller receives only the subject-facing attribute claims.
        Map<String, Object> subjectClaims = new HashMap<>(claims);
        PROTOCOL_CLAIMS.forEach(subjectClaims::remove);

        // buildMetadata receives both the full claims (to extract iss, iat, exp, vct, cnf) and
        // the stripped subjectClaims (to populate credentialClaims on the metadata object).
        PresentationMetadata metadata = buildMetadata(issuerJwt, sdJwt, kbJwt, claims, subjectClaims);

        return metadata;
    }

    /**
     * Dispatches issuer signature validation to the registered {@link CredentialSignatureValidator}
     * for the configured key resolution method.
     *
     * <p>When no method is configured, {@link CredentialSignatureValidator#TYPE_X5C} is used
     * as the HAIP default.</p>
     *
     * <p>{@code toUpperCase()} ensures the configured method string matches the upper-cased
     * constants defined in {@link CredentialSignatureValidator} regardless of how the
     * presentation definition was authored.</p>
     *
     * @param requestedCredential the credential request config carrying the key resolution method
     * @param issuerJwt           the issuer-signed JWT to validate
     * @throws VerificationException if no validator is registered or signature validation fails
     */
    private void validateSignature(RequestedCredential requestedCredential, SignedJWT issuerJwt)
            throws VerificationException {

        String method = requestedCredential.getKeyResolutionMethod();
        String validatorType = method != null ? method.toUpperCase() : CredentialSignatureValidator.TYPE_X5C;

        CredentialSignatureValidator validator =
                VerificationServiceComponentHolder.getInstance()
                        .getValidator(validatorType)
                        .orElseThrow(() -> new VerificationServerException(
                                VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                                "No credential signature validator registered for method: " + validatorType));

        // CredentialSignatureValidator is a String-based interface contract shared with other verifiers;
        // serialize() reconstructs the compact representation from already-parsed parts — no re-parsing occurs.
        validator.validateSignature(issuerJwt.serialize(), requestedCredential);
    }

    /**
     * Checks that the credential has not expired based on the {@code exp} claim.
     *
     * @param claimsSet the claims from the issuer-signed JWT
     * @throws VerificationClientException with {@link VerificationErrorCode#EXPIRED_CREDENTIAL}
     *                                     if the {@code exp} claim is present and in the past
     */
    private void verifyExpiration(JWTClaimsSet claimsSet) throws VerificationClientException {

        Date exp = claimsSet.getExpirationTime();
        if (exp != null && exp.before(new Date())) {
            throw new VerificationClientException(VerificationErrorCode.EXPIRED_CREDENTIAL,
                    "Credential has expired.");
        }
    }

    /**
     * Verifies each disclosure against the {@code _sd} hash array in the issuer-signed JWT
     * and merges the revealed claim values into the working claims map.
     *
     * <p>How SD-JWT selective disclosure works: the issuer replaces each selectively-disclosable
     * claim with a salted hash stored in the {@code _sd} array. The holder re-attaches only the
     * disclosures they wish to reveal. For each disclosure, this method recomputes the hash
     * using the algorithm in {@code _sd_alg} and checks if it appears in {@code _sd} — confirming
     * the disclosure was created by the issuer. Per RFC 9901 §6.1, a disclosure whose hash is
     * not found in {@code _sd} is evidence of tampering and causes an immediate rejection.</p>
     *
     * <p><strong>Limitation:</strong> supports flat SD-JWT VCs only. Array-element disclosures
     * and nested {@code _sd} arrays inside object claim values are not supported — any such
     * disclosure will have no matching hash in the top-level {@code _sd} and will be rejected.</p>
     *
     * @param claimsSet   the claims from the issuer-signed JWT
     * @param disclosures the disclosures attached to the SD-JWT presentation
     * @return a mutable claims map with all revealed disclosure values merged in
     * @throws VerificationException if a disclosure hash is not found in {@code _sd} or hashing fails
     */
    private Map<String, Object> extractAndApplyDisclosures(JWTClaimsSet claimsSet,
                                                            List<Disclosure> disclosures)
            throws VerificationException {

        // Start from the full claims map; strip SD-JWT internal fields that are not subject attributes.
        Map<String, Object> claims = new HashMap<>(claimsSet.getClaims());
        claims.remove(SDJWTConstants.CLAIM_SD);
        claims.remove(SDJWTConstants.CLAIM_SD_ALG);

        if (disclosures.isEmpty()) {
            return claims;
        }

        Object sdObj = claimsSet.getClaim(SDJWTConstants.CLAIM_SD);
        if (!(sdObj instanceof List)) {
            return claims;
        }
        @SuppressWarnings("unchecked")
        List<String> sdHashes = (List<String>) sdObj;
        if (sdHashes.isEmpty()) {
            return claims;
        }

        // _sd_alg defaults to sha-256 when absent (per SD-JWT VC spec §5.1).
        String sdAlg = (String) claimsSet.getClaim(SDJWTConstants.CLAIM_SD_ALG);
        try {
            for (Disclosure disclosure : disclosures) {
                String calculatedHash = disclosure.digest(sdAlg);
                if (!sdHashes.contains(calculatedHash)) {
                    // RFC 9901 §6.1: a disclosure whose hash is absent from _sd was not committed
                    // to by the issuer — reject the presentation as potentially tampered.
                    throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                            "Presentation contains a disclosure whose hash is not committed in the "
                                    + "issuer-signed JWT _sd array: " + calculatedHash);
                }
                claims.put(disclosure.getClaimName(), disclosure.getClaimValue());
            }
        } catch (SDJWTException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error verifying SD-JWT disclosures: " + e.getMessage(), e);
        }
        return claims;
    }

    /**
     * Validates the {@code vct} claim against the expected credential type in the presentation definition.
     *
     * @param req    the credential request config carrying the expected {@code vct} value
     * @param claims the merged claims map (issuer claims + disclosed values)
     * @throws VerificationClientException if the {@code vct} claim does not match the expected type
     */
    private void enforceVctType(RequestedCredential req, Map<String, Object> claims)
            throws VerificationClientException {

        String expectedType = req.getType();
        if (StringUtils.isBlank(expectedType)) {
            return;
        }
        Object vctObj = claims.get(VPConstants.JWTClaims.VCT);
        String actualVct = vctObj != null ? vctObj.toString() : null;
        if (!expectedType.equals(actualVct)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Credential '" + req.getCredentialId() + "' has vct '" + actualVct
                            + "' but '" + expectedType + "' is required.");
        }
    }

    /**
     * Verifies the KB-JWT when present, enforcing typ, signature, iat freshness, sd_hash, and nonce.
     *
     * @param sdJwt          the parsed SD-JWT presentation
     * @param claimsSet      the claims from the issuer-signed JWT (used to resolve {@code cnf})
     * @param expectedNonce  the nonce from the VP request, or {@code null} if holder binding is optional
     * @return the parsed KB-JWT for reuse in metadata extraction, or {@code null} if no KB-JWT is present
     * @throws VerificationException if KB-JWT is required but absent, or any KB-JWT check fails
     */
    private SignedJWT verifyKeyBinding(SDJWT sdJwt, JWTClaimsSet claimsSet, String expectedNonce,
                                       String expectedAudience)
            throws VerificationException {

        Object cnfRaw = claimsSet.getClaim(SDJWTConstants.CLAIM_CNF);
        if (cnfRaw != null && !(cnfRaw instanceof Map)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "cnf claim must be a JSON object, got: " + cnfRaw.getClass().getSimpleName());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) cnfRaw;

        if (!sdJwt.hasKeyBinding()) {
            if (expectedNonce != null) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                        "KB-JWT is required when a nonce is expected, but was not presented.");
            }
            if (cnf != null) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                        "KB-JWT is required when the credential contains a cnf claim, but was not presented.");
            }
            return null;
        }

        SignedJWT kbJwt;
        try {
            kbJwt = SignedJWT.parse(sdJwt.getKeyBindingJwt());
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse KB-JWT: " + e.getMessage(), e);
        }

        // 1. typ must be kb+jwt.
        if (kbJwt.getHeader().getType() == null
                || !KB_JWT_TYPE.equals(kbJwt.getHeader().getType().getType())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT typ header must be '" + KB_JWT_TYPE + "'.");
        }

        // 2. Resolve holder public key from cnf.jwk in the issuer-signed JWT.
        if (cnf == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "KB-JWT is present but issuer-signed JWT has no cnf claim.");
        }
        PublicKey holderPublicKey = resolveHolderPublicKey(cnf);

        // 3. Verify KB-JWT signature.
        String kbAlg = kbJwt.getHeader().getAlgorithm().getName();
        boolean kbSigValid;
        try {
            kbSigValid = SignatureVerifier.verifySignatureWithPublicKey(
                    sdJwt.getKeyBindingJwt(), holderPublicKey, kbAlg);
        } catch (VerificationException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT signature verification failed: " + e.getMessage(), e);
        }
        if (!kbSigValid) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT signature is invalid.");
        }

        JWTClaimsSet kbClaims;
        try {
            kbClaims = kbJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse KB-JWT claims: " + e.getMessage(), e);
        }

        // 4. Verify iat freshness.
        Date iat = kbClaims.getIssueTime();
        if (iat == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT is missing iat claim.");
        }
        if (Math.abs(System.currentTimeMillis() - iat.getTime()) > KB_JWT_IAT_TOLERANCE_MS) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT iat is outside the accepted 5-minute window.");
        }

        // 5. Verify sd_hash.
        verifyKbSdHash(sdJwt, claimsSet, kbClaims);

        // 6. Verify nonce.
        if (StringUtils.isNotBlank(expectedNonce)) {
            String kbNonce;
            try {
                kbNonce = kbClaims.getStringClaim(KB_JWT_NONCE_CLAIM);
            } catch (ParseException e) {
                throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                        "Failed to read nonce from KB-JWT: " + e.getMessage(), e);
            }
            if (StringUtils.isBlank(kbNonce)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "KB-JWT is missing nonce claim.");
            }
            if (!expectedNonce.equals(kbNonce)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "KB-JWT nonce does not match the expected nonce from the VP request.");
            }
        }

        // 7. Verify aud — the KB-JWT must be addressed to this verifier.
        if (StringUtils.isNotBlank(expectedAudience)) {
            List<String> kbAudience = kbClaims.getAudience();
            if (kbAudience == null || kbAudience.isEmpty()) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "KB-JWT is missing aud claim.");
            }
            if (!kbAudience.contains(expectedAudience)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "KB-JWT aud does not match the expected verifier client_id.");
            }
        }

        return kbJwt;
    }

    /**
     * Verifies the {@code sd_hash} claim in the KB-JWT against a fresh hash of the presentation string.
     *
     * @param sdJwt     the parsed SD-JWT presentation (used to reconstruct the presentation string)
     * @param claimsSet the claims from the issuer-signed JWT (used to read {@code _sd_alg})
     * @param kbClaims  the claims from the KB-JWT containing the {@code sd_hash} to verify
     * @throws VerificationException if {@code sd_hash} is absent, blank, or does not match
     */
    private void verifyKbSdHash(SDJWT sdJwt, JWTClaimsSet claimsSet,
                                 JWTClaimsSet kbClaims) throws VerificationException {

        String claimedSdHash;
        try {
            claimedSdHash = kbClaims.getStringClaim(KB_JWT_SD_HASH_CLAIM);
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to read sd_hash from KB-JWT: " + e.getMessage(), e);
        }
        if (StringUtils.isBlank(claimedSdHash)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT is missing sd_hash claim.");
        }

        // Build the presentation string: issuer-jwt~disc1~...~discN~
        String presentationString = new SDJWT(sdJwt.getIssuerSignedJwt(), sdJwt.getDisclosures()).serialize();

        String sdAlg = (String) claimsSet.getClaim(SDJWTConstants.CLAIM_SD_ALG);
        String jcaAlg = mapSdAlgToJca(sdAlg);
        byte[] hashBytes;
        try {
            hashBytes = MessageDigest.getInstance(jcaAlg)
                    .digest(presentationString.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Hash algorithm not available: " + jcaAlg, e);
        }

        if (!Base64URL.encode(hashBytes).toString().equals(claimedSdHash)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT sd_hash does not match the hash of the presented SD-JWT.");
        }
    }

    /**
     * Resolves the holder {@link PublicKey} from the {@code cnf.jwk} claim of the issuer-signed JWT.
     *
     * @param cnf the deserialized {@code cnf} claim map from the issuer-signed JWT
     * @return the holder's public key extracted from {@code cnf.jwk}
     * @throws VerificationException if {@code cnf.jwk} is absent, malformed, or contains private key material
     */
    @SuppressWarnings("unchecked")
    private PublicKey resolveHolderPublicKey(Map<String, Object> cnf) throws VerificationException {

        Object jwkObj = cnf.get(CNF_JWK_CLAIM);
        if (!(jwkObj instanceof Map)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Unsupported cnf format: only cnf.jwk is currently supported.");
        }
        JWK holderJwk;
        try {
            holderJwk = JWK.parse((Map<String, Object>) jwkObj);
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Failed to parse holder JWK from cnf claim: " + e.getMessage(), e);
        }
        if (holderJwk.isPrivate()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "cnf.jwk must not contain private key material.");
        }
        try {
            String keyType = holderJwk.getKeyType().getValue();
            switch (keyType) {
                case VerificationConstants.JWK_KEY_TYPE_EC:
                    return ((ECKey) holderJwk).toECPublicKey();
                case VerificationConstants.JWK_KEY_TYPE_RSA:
                    return ((RSAKey) holderJwk).toRSAPublicKey();
                default:
                    throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                            "Unsupported holder key type in cnf.jwk: " + keyType);
            }
        } catch (VerificationClientException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to extract holder public key from cnf.jwk: " + e.getMessage(), e);
        }
    }

    /**
     * Builds {@link PresentationMetadata} from already-parsed JWT objects and verified claims.
     * No additional parsing occurs here.
     *
     * @param issuerJwt     the parsed issuer-signed JWT (for algorithm and standard claim extraction)
     * @param sdJwt         the parsed SD-JWT presentation (currently unused but retained for future use)
     * @param kbJwt         the parsed KB-JWT, or {@code null} if no holder binding was present
     * @param claims        the full merged claims map (issuer claims + disclosed values)
     * @param subjectClaims the subject-attribute claims with protocol fields removed
     * @return a fully populated {@link PresentationMetadata} instance
     */
    @SuppressWarnings("unchecked")
    private PresentationMetadata buildMetadata(SignedJWT issuerJwt, SDJWT sdJwt,
                                                SignedJWT kbJwt,
                                                Map<String, Object> claims,
                                                Map<String, Object> subjectClaims) {

        PresentationMetadata.Builder builder = new PresentationMetadata.Builder()
                .vpFormat(getFormat())
                .presentationTime(System.currentTimeMillis());

        if (issuerJwt.getHeader() != null && issuerJwt.getHeader().getAlgorithm() != null) {
            builder.algorithm(issuerJwt.getHeader().getAlgorithm().getName());
        }

        if (claims.get(VPConstants.JWTClaims.ISS) != null) {
            builder.issuer(claims.get(VPConstants.JWTClaims.ISS).toString());
        }
        if (claims.get(VPConstants.JWTClaims.IAT) instanceof Date) {
            builder.issuedAt(((Date) claims.get(VPConstants.JWTClaims.IAT)).getTime());
        }
        if (claims.get(VPConstants.JWTClaims.EXP) instanceof Date) {
            builder.expiresAt(((Date) claims.get(VPConstants.JWTClaims.EXP)).getTime());
        }
        if (claims.get(VPConstants.JWTClaims.VCT) != null) {
            builder.credentialType(claims.get(VPConstants.JWTClaims.VCT).toString());
        }

        Object cnfObj = claims.get(VPConstants.JWTClaims.CNF);
        if (cnfObj instanceof Map) {
            Map<String, Object> cnf = (Map<String, Object>) cnfObj;
            Object jwkObj = cnf.get(VPConstants.JWTClaims.JWK);
            if (jwkObj instanceof Map) {
                try {
                    JWK jwk = JWK.parse((Map<String, Object>) jwkObj);
                    builder.holderBindingMethod(VerificationConstants.HOLDER_BINDING_CNF_JWK);
                    String keyType = jwk.getKeyType().getValue();
                    builder.holderKeyType(keyType);
                    if (VerificationConstants.JWK_KEY_TYPE_EC.equals(keyType)) {
                        builder.holderKeyCurve(((ECKey) jwk).getCurve().getName());
                    } else if (VerificationConstants.JWK_KEY_TYPE_OKP.equals(keyType)) {
                        builder.holderKeyCurve(((OctetKeyPair) jwk).getCurve().getName());
                    }
                } catch (Exception e) {
                    LOG.debug("Could not parse cnf.jwk for metadata: " + e.getMessage());
                }
            }
        }

        if (kbJwt != null) {
            try {
                builder.kbJwtVerified(true);
                JWTClaimsSet kbClaims = kbJwt.getJWTClaimsSet();
                if (kbClaims.getIssueTime() != null) {
                    builder.kbJwtPresentedAt(kbClaims.getIssueTime().getTime());
                }
                if (kbClaims.getAudience() != null && !kbClaims.getAudience().isEmpty()) {
                    builder.kbJwtAudience(kbClaims.getAudience().get(0));
                }
                String kbNonce = kbClaims.getStringClaim(VPConstants.JWTClaims.NONCE);
                if (StringUtils.isNotBlank(kbNonce)) {
                    builder.nonce(kbNonce);
                }
            } catch (Exception e) {
                LOG.debug("Could not extract KB-JWT metadata: " + e.getMessage());
            }
        }

        builder.credentialClaims(subjectClaims);

        return builder.build();
    }

    /**
     * Maps the SD-JWT {@code _sd_alg} identifier (lowercase IANA name, e.g. {@code "sha-256"})
     * to the JCA algorithm name expected by {@link MessageDigest#getInstance}.
     *
     * <p>SHA-256 is the mandatory-to-implement algorithm per the SD-JWT VC spec, so it is used
     * as the default when {@code _sd_alg} is absent or unrecognised.</p>
     *
     * @param sdAlg the {@code _sd_alg} value from the issuer-signed JWT, or {@code null}
     * @return the JCA algorithm name (e.g. {@code "SHA-256"})
     */
    private static String mapSdAlgToJca(String sdAlg) {

        if (sdAlg == null) {
            return VerificationConstants.SHA_256;
        }
        switch (sdAlg.toLowerCase()) {
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_256: return VerificationConstants.SHA_256;
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_384: return VerificationConstants.SHA_384;
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_512: return VerificationConstants.SHA_512;
            default: return VerificationConstants.SHA_256;
        }
    }
}
