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

package org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.internal.PresentationVerificationDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.SignatureValidationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.JwsUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationExceptionHandler;
import org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.FormatVerifier;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer.KeyResolutionMethod;
import org.wso2.carbon.identity.sdjwt.Disclosure;
import org.wso2.carbon.identity.sdjwt.SDJWT;
import org.wso2.carbon.identity.sdjwt.constant.SDJWTConstants;
import org.wso2.carbon.identity.sdjwt.exception.SDJWTException;
import org.wso2.carbon.identity.sdjwt.util.SDJWTUtil;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class verifies dc+sd-jwt credential presentations.
 */
public class SdJwtVcVerifier implements FormatVerifier {

    private static final Log LOG = LogFactory.getLog(SdJwtVcVerifier.class);

    private static final String KB_JWT_TYPE = "kb+jwt";
    private static final String KB_JWT_SD_HASH_CLAIM = "sd_hash";
    private static final long KB_JWT_IAT_TOLERANCE_MS = 2 * 60 * 1000L;

    @Override
    public String getFormat() {

        return Constants.VC_SD_JWT_FORMAT;
    }

    @Override
    public VerificationResponseDTO verifyCredential(VerificationRequestDTO requestDTO) throws VerificationException {

        SDJWT sdJwt;
        try {
            sdJwt = SDJWT.parse(requestDTO.getToken());
        } catch (SDJWTException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_SD_JWT_FORMAT);
        }

        SignedJWT issuerJwt;
        try {
            issuerJwt = SignedJWT.parse(sdJwt.getIssuerSignedJwt());
        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_ISSUER_JWT);
        }

        if (issuerJwt.getHeader().getType() == null
                || !SDJWTConstants.TYP_DC_SD_JWT.equals(issuerJwt.getHeader().getType().getType())) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_ISSUER_JWT);
        }

        // Validate issuer signature.
        String authenticatedIssuer = validateSignature(requestDTO.getCredential().getIdentifier(),
                requestDTO.getCredential().getIssuers(), issuerJwt);

        JWTClaimsSet claimsSet;
        try {
            claimsSet = issuerJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_ISSUER_JWT);
        }

        // Verify expiration.
        if (claimsSet.getExpirationTime() != null && claimsSet.getExpirationTime().before(new Date())) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.EXPIRED_CREDENTIAL);
        }
        // Verify not-before.
        if (claimsSet.getNotBeforeTime() != null && claimsSet.getNotBeforeTime().after(new Date())) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.CREDENTIAL_NOT_YET_VALID);
        }
        String sdAlg = (String) claimsSet.getClaim(SDJWTConstants.CLAIM_SD_ALG);

        // Resolve _sd digests and array placeholders (recursively, at any depth) into the actual
        // disclosed claim values, rejecting duplicate digests and disclosures that go unreferenced.
        Map<String, Object> subjectClaims = resolveDisclosedClaims(claimsSet, sdJwt.getDisclosures(), sdAlg);

        // Verify holder key binding: kb+jwt is signed by the wallet's key and covers this presentation.
        SignedJWT kbJwt = verifyKeyBinding(sdJwt, claimsSet, requestDTO.getExpectedNonce(),
                requestDTO.getExpectedAudience());
        String expectedType = requestDTO.getCredential().getType();
        Object vctClaim = claimsSet.getClaim(SDJWTConstants.CLAIM_VCT);
        if (StringUtils.isNotBlank(expectedType)
                && !expectedType.equals(vctClaim != null ? vctClaim.toString() : null)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.CREDENTIAL_TYPE_MISMATCH);
        }

        return buildVerificationResponse(requestDTO, issuerJwt, kbJwt, claimsSet, subjectClaims, authenticatedIssuer);
    }

    /**
     * Validates the issuer signature and resolves the authenticated issuer identity to report.
     *
     * @return The signing certificate's Subject DN for x5c, or the (here, already-authenticated) {@code
     *         iss} claim for jwks_uri/pem.
     */
    private String validateSignature(String credentialId, List<Issuer> issuers,
            SignedJWT issuerJwt) throws VerificationException {

        if (issuers == null || issuers.isEmpty()) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.ISSUER_NOT_FOUND,
                    new IllegalStateException("No trusted issuers found for credential."));
        }

        // Extract iss to match pem or jwks types by issuer URL.
        String iss;
        try {
            iss = issuerJwt.getJWTClaimsSet().getStringClaim(Constants.JWTClaims.ISS);
        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_ISSUER_JWT);
        }

        for (Issuer issuer : issuers) {
            KeyResolutionMethod method = issuer.getKeyResolutionMethod();
            if (method != KeyResolutionMethod.X5C) {
                // jwks_uri / pem: match by issuer URL.
                if (StringUtils.equals(iss, issuer.getIssuerUrl())) {
                    SignatureValidationContext context = new SignatureValidationContext(issuerJwt, issuer);
                    resolveSignatureValidator(method).validateSignature(context);
                    return context.getAuthenticatedSubject() != null ? context.getAuthenticatedSubject() : iss;
                }
            } else {
                // x5c: the trust anchor is determined by AKI matching inside the validator.
                CredentialSignatureValidator validator = resolveSignatureValidator(KeyResolutionMethod.X5C);
                SignatureValidationContext context = new SignatureValidationContext(issuerJwt, issuer);
                try {
                    validator.validateSignature(context);
                    return context.getAuthenticatedSubject() != null ? context.getAuthenticatedSubject() : iss;
                } catch (VerificationException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("x5c trust anchor '" + issuer.getIssuerUrl()
                                + "' did not validate the cert chain for credential '" + credentialId + "'.", e);
                    }
                }
            }
        }

        throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.UNTRUSTED_ISSUER);
    }

    private CredentialSignatureValidator resolveSignatureValidator(KeyResolutionMethod resolutionMethod) throws
            VerificationServerException {

        return PresentationVerificationDataHolder.getInstance()
                .getCredentialSignatureValidator(resolutionMethod.name())
                .orElseThrow(() -> VerificationExceptionHandler.handleServerException(
                        VerificationErrorCode.VALIDATOR_NOT_REGISTERED,
                        new IllegalStateException(
                                "No validator registered for key resolution method: " + resolutionMethod.name())));
    }


    /**
     * Reconstructs the disclosed claim set from the issuer-signed JWT payload and the presentation's
     * Disclosures, per the SD-JWT verification algorithm (RFC 9901 Section 7.1): {@code _sd} digest
     * arrays and {@code "..."} array placeholders are resolved recursively at every nesting level, not
     * just the top level. The same digest value appearing more than once anywhere in the structure, or
     * a Disclosure the wallet sent that is never referenced by any digest, causes rejection.
     *
     * @param claimsSet   Claims from the issuer-signed JWT.
     * @param disclosures Disclosures attached to the SD-JWT presentation.
     * @param sdAlgorithm _sd_alg value from the issuer-signed JWT, or null to default to sha-256.
     * @return The claim set with all resolvable _sd digests and array placeholders replaced by their
     *         disclosed values.
     * @throws VerificationException If a digest is duplicated, a disclosure is unreferenced, or hashing fails.
     */
    private Map<String, Object> resolveDisclosedClaims(JWTClaimsSet claimsSet, List<Disclosure> disclosures,
            String sdAlgorithm) throws VerificationException {

        String algorithm = sdAlgorithm != null ? sdAlgorithm : SDJWTConstants.DEFAULT_HASH_ALGORITHM;
        Map<String, Disclosure> digestToDisclosure = mapDisclosuresByDigest(disclosures, algorithm);
        Set<String> seenDigests = new HashSet<>();
        Set<Disclosure> usedDisclosures = new HashSet<>();

        Map<String, Object> resolvedClaims = resolveDisclosures(new HashMap<>(claimsSet.getClaims()),
                digestToDisclosure, seenDigests, usedDisclosures);

        for (Disclosure disclosure : disclosures) {
            if (!usedDisclosures.contains(disclosure)) {
                throw VerificationExceptionHandler.handleClientException(
                        VerificationErrorCode.DISCLOSURE_HASH_MISMATCH);
            }
        }
        return resolvedClaims;
    }

    private Map<String, Disclosure> mapDisclosuresByDigest(List<Disclosure> disclosures, String sdAlgorithm)
            throws VerificationException {

        Map<String, Disclosure> digestToDisclosure = new HashMap<>();
        try {
            for (Disclosure disclosure : disclosures) {
                digestToDisclosure.put(disclosure.digest(sdAlgorithm), disclosure);
            }
        } catch (SDJWTException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.DISCLOSURE_DIGEST_ERROR, e);
        }
        return digestToDisclosure;
    }

    /**
     * Resolves the {@code _sd} digest array of a single object (in place) by looking up each digest's
     * matching Disclosure, then recurses into every remaining value (including newly disclosed ones) to
     * resolve further nested {@code _sd} arrays and array placeholders.
     */
    private Map<String, Object> resolveDisclosures(Map<String, Object> claims,
            Map<String, Disclosure> digestToDisclosure, Set<String> seenDigests, Set<Disclosure> usedDisclosures)
            throws VerificationException {

        Object sdClaim = claims.remove(SDJWTConstants.CLAIM_SD);
        claims.remove(SDJWTConstants.CLAIM_SD_ALG);

        if (sdClaim instanceof List) {
            for (Object digestEntry : (List<?>) sdClaim) {
                if (!(digestEntry instanceof String)) {
                    continue;
                }
                String digest = (String) digestEntry;
                recordDigest(digest, seenDigests);

                Disclosure disclosure = digestToDisclosure.get(digest);
                if (disclosure != null && !disclosure.isArrayElement()) {
                    usedDisclosures.add(disclosure);
                    Object value = resolveValue(disclosure.getClaimValue(), digestToDisclosure, seenDigests,
                            usedDisclosures);
                    claims.put(disclosure.getClaimName(), value);
                }
                // Else: no matching Disclosure - that claim simply was not selectively disclosed.
            }
        }

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            entry.setValue(resolveValue(entry.getValue(), digestToDisclosure, seenDigests, usedDisclosures));
        }
        return claims;
    }

    /**
     * Resolves {@code "..."} array-element placeholders by looking up each placeholder's matching
     * Disclosure. Placeholders with no matching Disclosure are dropped from the result, per spec.
     */
    private List<Object> resolveArrayDisclosures(List<Object> array, Map<String, Disclosure> digestToDisclosure,
            Set<String> seenDigests, Set<Disclosure> usedDisclosures) throws VerificationException {

        List<Object> resolved = new ArrayList<>();
        for (Object element : array) {
            String placeholderDigest = asArrayPlaceholderDigest(element);
            if (placeholderDigest != null) {
                recordDigest(placeholderDigest, seenDigests);

                Disclosure disclosure = digestToDisclosure.get(placeholderDigest);
                if (disclosure != null && disclosure.isArrayElement()) {
                    usedDisclosures.add(disclosure);
                    resolved.add(resolveValue(disclosure.getClaimValue(), digestToDisclosure, seenDigests,
                            usedDisclosures));
                }
                // Else: no matching Disclosure - the undisclosed element is omitted, per spec.
                continue;
            }
            resolved.add(resolveValue(element, digestToDisclosure, seenDigests, usedDisclosures));
        }
        return resolved;
    }

    @SuppressWarnings("unchecked")
    private Object resolveValue(Object value, Map<String, Disclosure> digestToDisclosure, Set<String> seenDigests,
            Set<Disclosure> usedDisclosures) throws VerificationException {

        if (value instanceof Map) {
            return resolveDisclosures(new HashMap<>((Map<String, Object>) value), digestToDisclosure, seenDigests,
                    usedDisclosures);
        }
        if (value instanceof List) {
            return resolveArrayDisclosures(new ArrayList<>((List<Object>) value), digestToDisclosure, seenDigests,
                    usedDisclosures);
        }
        return value;
    }

    /**
     * Returns the digest carried by an SD-JWT array-element placeholder (an object with exactly one key,
     * {@code "..."}, mapped to a digest string), or {@code null} if {@code element} is not such a
     * placeholder.
     */
    private static String asArrayPlaceholderDigest(Object element) {

        if (!(element instanceof Map)) {
            return null;
        }
        Map<?, ?> map = (Map<?, ?>) element;
        Object digest = map.get(SDJWTConstants.ARRAY_ELEMENT_KEY);
        return map.size() == 1 && digest instanceof String ? (String) digest : null;
    }

    private static void recordDigest(String digest, Set<String> seenDigests) throws VerificationException {

        if (!seenDigests.add(digest)) {
            throw VerificationExceptionHandler.handleClientException(
                    VerificationErrorCode.DUPLICATE_DISCLOSURE_DIGEST);
        }
    }

    /**
     * Verifies the KB-JWT when present, enforcing typ, signature, iat freshness, sd_hash, and nonce.
     *
     * @param sdJwt            Parsed SD-JWT presentation.
     * @param claimsSet        Claims from the issuer-signed JWT.
     * @param expectedNonce    Nonce from the VP request, or null if holder binding is optional.
     * @param expectedAudience Verifier client_id from the VP request, or null if aud is not enforced.
     * @return Parsed KB-JWT, or null if no KB-JWT is present.
     * @throws VerificationException If KB-JWT is required but absent, or any KB-JWT check fails.
     */
    private SignedJWT verifyKeyBinding(SDJWT sdJwt, JWTClaimsSet claimsSet, String expectedNonce,
            String expectedAudience) throws VerificationException {

        if (!sdJwt.hasKeyBinding()) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.MISSING_KEY_BINDING_JWT);
        }

        SignedJWT kbJwt;
        try {
            kbJwt = SignedJWT.parse(sdJwt.getKeyBindingJwt());
        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_KB_JWT);
        }

        if (kbJwt.getHeader().getType() == null
                || !KB_JWT_TYPE.equals(kbJwt.getHeader().getType().getType())) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_KB_JWT);
        }

        Object cnfClaim = claimsSet.getClaim(SDJWTConstants.CLAIM_CNF);
        if (!(cnfClaim instanceof Map)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_HOLDER_BINDING);
        }
        @SuppressWarnings("unchecked")
        PublicKey holderPublicKey = resolveHolderPublicKey((Map<String, Object>) cnfClaim);

        boolean isKbSignatureValid;
        try {
            isKbSignatureValid = JwsUtil.verifySignatureWithPublicKey(
                    kbJwt, holderPublicKey, kbJwt.getHeader().getAlgorithm().getName());
        } catch (VerificationException e) {
            isKbSignatureValid = false;
        }
        if (!isKbSignatureValid) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_KB_JWT);
        }

        JWTClaimsSet kbClaims;
        String sdHash;
        String kbNonce;
        try {
            kbClaims = kbJwt.getJWTClaimsSet();
            sdHash = kbClaims.getStringClaim(KB_JWT_SD_HASH_CLAIM);
            kbNonce = kbClaims.getStringClaim(Constants.JWTClaims.NONCE);
        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_KB_JWT);
        }

        Date iat = kbClaims.getIssueTime();
        if (iat == null) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_KB_JWT);
        }
        if (Math.abs(System.currentTimeMillis() - iat.getTime()) > KB_JWT_IAT_TOLERANCE_MS) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.STALE_KB_JWT);
        }

        verifyKbSdHash(sdJwt, (String) claimsSet.getClaim(SDJWTConstants.CLAIM_SD_ALG), sdHash);

        if (StringUtils.isNotBlank(expectedNonce) && !expectedNonce.equals(kbNonce)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.NONCE_MISMATCH);
        }

        if (StringUtils.isNotBlank(expectedAudience)) {
            List<String> kbAudience = kbClaims.getAudience();
            if (kbAudience == null || !kbAudience.contains(expectedAudience)) {
                throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.AUDIENCE_MISMATCH);
            }
        }

        return kbJwt;
    }

    /**
     * Verifies the sd_hash claim in the KB-JWT against a fresh hash of the presentation string.
     *
     * @param sdJwt  Parsed SD-JWT presentation.
     * @param sdAlg  _sd_alg value from the issuer-signed JWT.
     * @param sdHash sd_hash value from the KB-JWT claims.
     * @throws VerificationException If sd_hash is absent, blank, or does not match.
     */
    private void verifyKbSdHash(SDJWT sdJwt, String sdAlg, String sdHash)
            throws VerificationException {

        if (StringUtils.isBlank(sdHash)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.SD_HASH_MISMATCH);
        }

        // Build the presentation string: issuer-jwt~disc1~...~discN~
        String presentationString = new SDJWT(sdJwt.getIssuerSignedJwt(), sdJwt.getDisclosures()).serialize();

        String jcaAlg = mapSdAlgToJca(sdAlg);
        byte[] hashBytes;
        try {
            hashBytes = MessageDigest.getInstance(jcaAlg)
                    .digest(presentationString.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.INTERNAL_SERVER_ERROR, e);
        }

        if (!MessageDigest.isEqual(hashBytes, Base64URL.from(sdHash).decode())) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.SD_HASH_MISMATCH);
        }
    }

    /**
     * Resolves the holder public key from the cnfClaim.jwk claim of the issuer-signed JWT.
     *
     * @param cnfClaim Deserialized cnfClaim claim map from the issuer-signed JWT.
     * @return Holder's public key.
     * @throws VerificationClientException If cnfClaim.jwk is absent, malformed, or contains private key material.
     */
    @SuppressWarnings("unchecked")
    private PublicKey resolveHolderPublicKey(Map<String, Object> cnfClaim) throws VerificationClientException {

        Object jwkObject = cnfClaim.get(Constants.JWTClaims.JWK);
        if (!(jwkObject instanceof Map)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_HOLDER_BINDING);
        }
        JWK holderJwk;
        try {
            holderJwk = JWK.parse((Map<String, Object>) jwkObject);
        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_HOLDER_BINDING);
        }
        if (holderJwk.isPrivate() || !(holderJwk instanceof AsymmetricJWK)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_HOLDER_BINDING);
        }
        try {
            return ((AsymmetricJWK) holderJwk).toPublicKey();
        } catch (JOSEException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_HOLDER_BINDING);
        }
    }

    /**
     * Assembles a verification response from already-parsed JWT objects.
     *
     * @param requestDTO    Verification DTO carrying the credential ID and request config.
     * @param issuerJwt     Parsed issuer-signed JWT.
     * @param kbJwt         Parsed KB-JWT, or null if no holder binding was present.
     * @param claimsSet     Claims from the issuer-signed JWT.
     * @param subjectClaims Fully-resolved claim set, with all _sd digests and array placeholders replaced
     *                      by their disclosed values.
     * @param authenticatedIssuer The authenticated issuer identity established during signature
     *                      validation (see {@link #validateSignature}), reported in place of the token's
     *                      self-asserted {@code iss} claim.
     * @return Verification response DTO.
     */
    private VerificationResponseDTO buildVerificationResponse(VerificationRequestDTO requestDTO,
            SignedJWT issuerJwt, SignedJWT kbJwt,
            JWTClaimsSet claimsSet,
            Map<String, Object> subjectClaims,
            String authenticatedIssuer) {

        VerificationResponseDTO verificationResponse = new VerificationResponseDTO();
        verificationResponse.setCredentialId(requestDTO.getCredential().getIdentifier());
        verificationResponse.setCredentialFormat(getFormat());
        verificationResponse.setVerifiedAt(System.currentTimeMillis());

        if (issuerJwt.getHeader() != null && issuerJwt.getHeader().getAlgorithm() != null) {
            verificationResponse.setSigningAlgorithm(issuerJwt.getHeader().getAlgorithm().getName());
        }

        if (authenticatedIssuer != null) {
            verificationResponse.setIssuer(authenticatedIssuer);
        }
        if (claimsSet.getIssueTime() != null) {
            verificationResponse.setIssuedAt(claimsSet.getIssueTime().getTime());
        }
        if (claimsSet.getExpirationTime() != null) {
            verificationResponse.setExpiresAt(claimsSet.getExpirationTime().getTime());
        }
        Object vct = claimsSet.getClaim(SDJWTConstants.CLAIM_VCT);
        if (vct != null) {
            verificationResponse.setVct(vct.toString());
        }

        if (kbJwt != null) {
            verificationResponse.setKbJwtVerified(true);
            try {
                String kbNonce = kbJwt.getJWTClaimsSet().getStringClaim(Constants.JWTClaims.NONCE);
                if (StringUtils.isNotBlank(kbNonce)) {
                    verificationResponse.setNonce(kbNonce);
                }
            } catch (ParseException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not extract nonce from KB-JWT claims.", e);
                }
            }
        }

        verificationResponse.setSubjectClaims(subjectClaims);

        return verificationResponse;
    }

    /**
     * Maps the SD-JWT _sd_alg identifier to the JCA algorithm name, defaulting to sha-256 only when
     * _sd_alg is absent. An unrecognized (but present) value is rejected rather than silently downgraded.
     *
     * @param sdAlg _sd_alg value from the issuer-signed JWT, or null.
     * @return JCA algorithm name.
     * @throws VerificationException If sdAlg is present but not a supported hash algorithm.
     */
    private static String mapSdAlgToJca(String sdAlg) throws VerificationException {

        try {
            return SDJWTUtil.toJavaAlgorithm(sdAlg != null ? sdAlg : SDJWTConstants.DEFAULT_HASH_ALGORITHM);
        } catch (SDJWTException e) {
            throw VerificationExceptionHandler.handleClientException(
                    VerificationErrorCode.UNSUPPORTED_SD_HASH_ALGORITHM);
        }
    }
}
