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
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery.CredentialQuery;
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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Verifier for {@code dc+sd-jwt} credential presentations.
 */
public class SdJwtVerifier implements Verifier {

    private static final Log LOG = LogFactory.getLog(SdJwtVerifier.class);

    private static final String KB_JWT_TYPE = "kb+jwt";
    private static final String KB_JWT_SD_HASH_CLAIM = "sd_hash";
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
    public CredentialVerificationResult verify(CredentialVerificationContext ctx) throws VerificationException {

        SDJWT sdJwt;
        try {
            sdJwt = SDJWT.parse(ctx.getCredentialToken());
        } catch (SDJWTException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse SD-JWT: " + e.getMessage(), e);
        }

        SignedJWT issuerJwt;
        try {
            issuerJwt = SignedJWT.parse(sdJwt.getIssuerSignedJwt());
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse issuer-signed JWT: " + e.getMessage(), e);
        }
        validateSignature(ctx.getCredentialQuery(), issuerJwt);

        JWTClaimsSet claimsSet;
        try {
            claimsSet = issuerJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to read claims from issuer-signed JWT: " + e.getMessage(), e);
        }

        verifyExpiration(claimsSet);
        Map<String, Object> claims = extractAndApplyDisclosures(claimsSet, sdJwt.getDisclosures());
        SignedJWT kbJwt = verifyKeyBinding(sdJwt, claimsSet, ctx.getExpectedNonce(), ctx.getExpectedAudience());
        enforceVctType(ctx.getCredentialQuery(), claims);

        Map<String, Object> subjectClaims = new HashMap<>(claims);
        PROTOCOL_CLAIMS.forEach(subjectClaims::remove);

        PresentationMetadata metadata = buildMetadata(issuerJwt, kbJwt, claims, subjectClaims);

        return new CredentialVerificationResult(metadata, subjectClaims);
    }

    /**
     * Dispatches issuer signature validation to the registered {@link CredentialSignatureValidator}
     * matching the credential's configured issuer configs.
     *
     * <p>For {@code jwks_uri} and {@code pem} methods the config is selected by matching the
     * credential's {@code iss} claim against the configured {@code issuerUrl}. For {@code x5c}
     * configs there is no issuer URL; each x5c config is tried in order until one succeeds —
     * the AKI/SKI matching inside {@link
     * org.wso2.carbon.identity.openid4vc.presentation.verification.validators.impl.X5cSignatureValidator}
     * determines the correct trust anchor.</p>
     *
     * @param credentialQuery the credential request config carrying the issuer configs
     * @param issuerJwt the parsed issuer-signed JWT to validate
     * @throws VerificationException if no matching config is found or signature validation fails
     */
    private void validateSignature(CredentialQuery credentialQuery, SignedJWT issuerJwt)
            throws VerificationException {

        List<DcqlQuery.IssuerConfig> issuerConfigs = credentialQuery.getIssuerConfigs();
        if (issuerConfigs == null || issuerConfigs.isEmpty()) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "No issuer configurations are defined for credential '" +
                            credentialQuery.getId() + "'.");
        }

        // Extract iss to match non-x5c configs by issuer URL.
        String iss;
        try {
            iss = issuerJwt.getJWTClaimsSet().getStringClaim(VPConstants.JWTClaims.ISS);
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to read iss claim from issuer JWT: " + e.getMessage(), e);
        }

        // Match jwks_uri / pem configs by issuer URL first.
        for (DcqlQuery.IssuerConfig config : issuerConfigs) {
            String method = config.getKeySourceType();
            if (CredentialSignatureValidator.TYPE_X5C.equalsIgnoreCase(method)) {
                continue;
            }
            if (!StringUtils.equals(iss, config.getIssuerUrl())) {
                continue;
            }
            resolveValidator(method).validateSignature(issuerJwt.serialize(), config);
            return;
        }

        // For x5c configs the trust anchor is determined by AKI matching inside the validator.
        // Try each x5c config; the first one that validates the chain is accepted.
        VerificationException lastX5cException = null;
        int x5cIndex = 0;
        for (DcqlQuery.IssuerConfig config : issuerConfigs) {
            if (!CredentialSignatureValidator.TYPE_X5C.equalsIgnoreCase(config.getKeySourceType())) {
                continue;
            }
            try {
                resolveValidator(CredentialSignatureValidator.TYPE_X5C)
                        .validateSignature(issuerJwt.serialize(), config);
                return;
            } catch (VerificationException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("x5c config [" + x5cIndex + "] did not match.", e);
                }
                lastX5cException = e;
            }
            x5cIndex++;
        }

        if (lastX5cException != null) {
            throw lastX5cException;
        }
        throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                "No matching issuer configuration found for iss '" + iss +
                        "' on credential '" + credentialQuery.getId() + "'.");
    }

    private CredentialSignatureValidator resolveValidator(String method) throws VerificationServerException {

        if (method == null) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Issuer config is missing keySourceType.");
        }
        String validatorType = method.toUpperCase(Locale.ROOT);
        return VerificationServiceComponentHolder.getInstance()
                .getValidator(validatorType)
                .orElseThrow(() -> new VerificationServerException(
                        VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        "No credential signature validator registered for method: " + validatorType));
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
            List<Disclosure> disclosures) throws VerificationException {

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
     * @param credentialQuery the credential request config carrying the expected {@code vct} value
     * @param claims the merged claims map (issuer claims + disclosed values)
     * @throws VerificationClientException if the {@code vct} claim does not match the expected type
     */
    private void enforceVctType(CredentialQuery credentialQuery, Map<String, Object> claims)
            throws VerificationClientException {

        String expectedType = credentialQuery.getVct();
        if (StringUtils.isBlank(expectedType)) {
            return;
        }
        Object vctObj = claims.get(SDJWTConstants.CLAIM_VCT);
        String actualVct = vctObj != null ? vctObj.toString() : null;
        if (!expectedType.equals(actualVct)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Credential '" + credentialQuery.getVct() + "' has vct '" + actualVct
                            + "' but '" + expectedType + "' is required.");
        }
    }

    /**
     * Verifies the KB-JWT when present, enforcing typ, signature, iat freshness, sd_hash, and nonce.
     *
     * @param sdJwt          the parsed SD-JWT presentation
     * @param claimsSet      the claims from the issuer-signed JWT (used to resolve {@code cnf})
     * @param expectedNonce the nonce from the VP request, or {@code null} if holder binding is optional
     * @param expectedAudience the verifier client_id from the VP request, or {@code null} if aud is not enforced
     * @return the parsed KB-JWT for reuse in metadata extraction, or {@code null} if no KB-JWT is present
     * @throws VerificationException if KB-JWT is required but absent, or any KB-JWT check fails
     */
    private SignedJWT verifyKeyBinding(SDJWT sdJwt, JWTClaimsSet claimsSet, String expectedNonce,
            String expectedAudience) throws VerificationException {

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

        if (kbJwt.getHeader().getType() == null
                || !KB_JWT_TYPE.equals(kbJwt.getHeader().getType().getType())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT typ header must be '" + KB_JWT_TYPE + "'.");
        }

        if (cnf == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "KB-JWT is present but issuer-signed JWT has no cnf claim.");
        }
        PublicKey holderPublicKey = resolveHolderPublicKey(cnf);

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

        Date iat = kbClaims.getIssueTime();
        if (iat == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT is missing iat claim.");
        }
        if (Math.abs(System.currentTimeMillis() - iat.getTime()) > KB_JWT_IAT_TOLERANCE_MS) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "KB-JWT iat is outside the accepted 5-minute window.");
        }

        verifyKbSdHash(sdJwt, claimsSet, kbClaims);

        if (StringUtils.isNotBlank(expectedNonce)) {
            String kbNonce;
            try {
                kbNonce = kbClaims.getStringClaim(VPConstants.JWTClaims.NONCE);
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

        if (!MessageDigest.isEqual(hashBytes, Base64URL.from(claimedSdHash).decode())) {
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

        Object jwkObj = cnf.get(VPConstants.JWTClaims.JWK);
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
                case VerificationConstants.JWK_KEY_TYPE_OKP:
                    return ((OctetKeyPair) holderJwk).toPublicKey();
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
     * @param issuerJwt the parsed issuer-signed JWT (for algorithm and standard claim extraction)
     * @param kbJwt the parsed KB-JWT, or {@code null} if no holder binding was present
     * @param claims the full merged claims map (issuer claims + disclosed values)
     * @param subjectClaims the subject-attribute claims with protocol fields removed
     * @return a fully populated {@link PresentationMetadata} instance
     */
    @SuppressWarnings("unchecked")
    private PresentationMetadata buildMetadata(SignedJWT issuerJwt, SignedJWT kbJwt,
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
        if (claims.get(SDJWTConstants.CLAIM_VCT) != null) {
            builder.credentialType(claims.get(SDJWTConstants.CLAIM_VCT).toString());
        }

        Object cnfObj = claims.get(SDJWTConstants.CLAIM_CNF);
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
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Could not parse cnf.jwk for metadata.", e);
                    }
                }
            }
        }

        if (kbJwt != null) {
            try {
                JWTClaimsSet kbClaims = kbJwt.getJWTClaimsSet();
                builder.kbJwtVerified(true);
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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not extract KB-JWT metadata.", e);
                }
            }
        }

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
        switch (sdAlg.toLowerCase(Locale.ROOT)) {
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_256: return VerificationConstants.SHA_256;
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_384: return VerificationConstants.SHA_384;
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_512: return VerificationConstants.SHA_512;
            default: return VerificationConstants.SHA_256;
        }
    }
}
