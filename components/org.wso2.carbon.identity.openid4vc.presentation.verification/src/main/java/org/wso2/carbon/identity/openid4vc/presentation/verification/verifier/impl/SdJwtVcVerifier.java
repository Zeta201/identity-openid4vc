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
import org.wso2.carbon.identity.openid4vc.presentation.verification.constant.VerificationConstants;
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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

        // Validate issuer signature.
        validateSignature(requestDTO.getCredential().getIdentifier(),
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
        @SuppressWarnings("unchecked")
        List<String> sdHashes = claimsSet.getClaim(SDJWTConstants.CLAIM_SD) instanceof List
                ? (List<String>) claimsSet.getClaim(SDJWTConstants.CLAIM_SD) : null;
        String sdAlg = (String) claimsSet.getClaim(SDJWTConstants.CLAIM_SD_ALG);

        // Verify each disclosure's hash appears in the issuer-signed _sd array.
        verifyDisclosureHashes(sdHashes, sdAlg, sdJwt.getDisclosures());

        // Verify holder key binding: kb+jwt is signed by the wallet's key and covers this presentation.
        SignedJWT kbJwt = verifyKeyBinding(sdJwt, claimsSet, requestDTO.getExpectedNonce(),
                requestDTO.getExpectedAudience());
        String expectedType = requestDTO.getCredential().getType();
        Object vctClaim = claimsSet.getClaim(SDJWTConstants.CLAIM_VCT);
        if (StringUtils.isNotBlank(expectedType)
                && !expectedType.equals(vctClaim != null ? vctClaim.toString() : null)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.CREDENTIAL_TYPE_MISMATCH);
        }

        Map<String, Object> subjectClaims = new HashMap<>();
        for (Disclosure disclosure : sdJwt.getDisclosures()) {
            subjectClaims.put(disclosure.getClaimName(), disclosure.getClaimValue());
        }

        return buildVerificationResponse(requestDTO, issuerJwt, kbJwt, claimsSet, subjectClaims);
    }

    private void validateSignature(String credentialId, List<Issuer> issuers,
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
                    resolveSignatureValidator(method).validateSignature(
                            new SignatureValidationContext(issuerJwt, issuer));
                    return;
                }
            } else {
                // x5c: the trust anchor is determined by AKI matching inside the validator.
                CredentialSignatureValidator validator = resolveSignatureValidator(KeyResolutionMethod.X5C);
                try {
                    validator.validateSignature(new SignatureValidationContext(issuerJwt, issuer));
                    return;
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
     * Verifies each disclosure against the _sd hash array in the issuer-signed JWT.
     *
     * @param sdHashes    _sd hash list from the issuer-signed JWT, or null if absent.
     * @param sdAlgorithm _sd_alg value, or null to default to sha-256.
     * @param disclosures Disclosures attached to the SD-JWT presentation.
     * @throws VerificationException If a disclosure hash is not found in _sd or hashing fails.
     */
    private void verifyDisclosureHashes(List<String> sdHashes, String sdAlgorithm,
            List<Disclosure> disclosures) throws VerificationException {

        if (disclosures.isEmpty()) {
            return;
        }
        if (sdHashes == null || sdHashes.isEmpty()) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.DISCLOSURE_HASH_MISMATCH);
        }

        try {
            for (Disclosure disclosure : disclosures) {
                String calculatedHash = disclosure.digest(sdAlgorithm);
                if (!sdHashes.contains(calculatedHash)) {
                    throw VerificationExceptionHandler.handleClientException(
                            VerificationErrorCode.DISCLOSURE_HASH_MISMATCH);
                }
            }
        } catch (SDJWTException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.DISCLOSURE_DIGEST_ERROR, e);
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
     * @param subjectClaims Subject-attribute claims extracted from the disclosures.
     * @return Verification response DTO.
     */
    private VerificationResponseDTO buildVerificationResponse(VerificationRequestDTO requestDTO,
            SignedJWT issuerJwt, SignedJWT kbJwt,
            JWTClaimsSet claimsSet,
            Map<String, Object> subjectClaims) {

        VerificationResponseDTO verificationResponse = new VerificationResponseDTO();
        verificationResponse.setCredentialId(requestDTO.getCredential().getIdentifier());
        verificationResponse.setCredentialFormat(getFormat());
        verificationResponse.setVerifiedAt(System.currentTimeMillis());

        if (issuerJwt.getHeader() != null && issuerJwt.getHeader().getAlgorithm() != null) {
            verificationResponse.setSigningAlgorithm(issuerJwt.getHeader().getAlgorithm().getName());
        }

        if (claimsSet.getIssuer() != null) {
            verificationResponse.setIssuer(claimsSet.getIssuer());
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
     * Maps the SD-JWT _sd_alg identifier to the JCA algorithm name.
     *
     * @param sdAlg _sd_alg value from the issuer-signed JWT, or null.
     * @return JCA algorithm name.
     */
    private static String mapSdAlgToJca(String sdAlg) {

        if (sdAlg == null) {
            return VerificationConstants.SHA_256;
        }
        switch (sdAlg.toLowerCase(Locale.ROOT)) {
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_384:
                return VerificationConstants.SHA_384;
            case VerificationConstants.SD_JWT_HASH_ALG_SHA_512:
                return VerificationConstants.SHA_512;
            default:
                return VerificationConstants.SHA_256;
        }
    }
}
