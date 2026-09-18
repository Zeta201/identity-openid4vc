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

package org.wso2.carbon.identity.openid4vc.presentation.core.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreAuditLogger;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.PresentationCoreConstants;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionRespDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreExceptionHandler;
import org.wso2.carbon.identity.openid4vc.presentation.core.internal.PresentationCoreDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSessionStatus;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationSessionService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.util.DcqlUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;


/**
 * Session lifecycle manager for VP authorization flows.
 *
 * <p>Responsible for initiating, retrieving, and removing VP flow sessions,
 * and for building and signing the OpenID4VP authorization request JWT.
 */
public class PresentationCoreServiceImpl implements PresentationSessionService, PresentationRequestService {

    private static final Log LOG = LogFactory.getLog(PresentationCoreServiceImpl.class);
    private static final PresentationCoreAuditLogger AUDIT_LOGGER = PresentationCoreAuditLogger.getInstance();
    private static final long SESSION_TIMEOUT_MS = 120_000L;
    private static final Gson GSON = new GsonBuilder().create();
    private static final Type VP_TOKEN_TYPE = new TypeToken<Map<String, Object>>() { }.getType();

    @Override
    public PresentationRequestResponseDTO startPresentationSession(String presentationDefinitionId, String tenantDomain)
            throws PresentationCoreException {

        String requestId = UUID.randomUUID().toString();

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }

        String nonce = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + SESSION_TIMEOUT_MS;

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        PresentationDefinition presentationDefinition;
        try {
            presentationDefinition = PresentationCoreDataHolder.getInstance().getPresentationDefinitionManager()
                    .getPresentationDefinitionById(presentationDefinitionId, tenantId);
        } catch (PresentationManagementException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.PRESENTATION_DEFINITION_ERROR, e);
        }
        if (presentationDefinition == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, presentationDefinitionId);
        }

        VPTenantConfig vpTenantConfig = PresentationCoreDataHolder.getInstance()
                .getVpConfigService().getVPConfig(tenantDomain);
        String scheme = vpTenantConfig.getClientIdScheme();
        String responseMode = vpTenantConfig.getResponseMode();
        String clientId = PresentationCoreUtil.buildClientId(scheme, tenantDomain);
        // EC P-256 key pair required only for direct_post.jwt to let the wallet ECDH-encrypt its response.
        // Public half is embedded in the request JWT; private half is kept in the session for decryption.
        String ephemeralPrivateKeyJwk = PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT.equals(responseMode)
                ? generateEphemeralKey(requestId)
                : null;

        String responseUri = PresentationCoreUtil.buildResponseUri(tenantDomain);
        String requestUri = PresentationCoreUtil.buildRequestUri(tenantDomain, requestId);
        String walletUrl = PresentationCoreUtil.buildWalletUrl(clientId, requestUri);

        VPSession session = new VPSession.Builder()
                .presentationDefinition(presentationDefinition)
                .tenantDomain(tenantDomain)
                .tenantId(tenantId)
                .status(VPSessionStatus.ACTIVE)
                .nonce(nonce)
                .ephemeralPrivateKeyJwk(ephemeralPrivateKeyJwk)
                .expiresAt(expiresAt)
                .clientId(clientId)
                .clientIdScheme(scheme)
                .responseUri(responseUri)
                .responseMode(responseMode)
                .walletUrl(walletUrl)
                .build();

        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), tenantId);
        AUDIT_LOGGER.logVPSessionInitiated(requestId, presentationDefinition, tenantDomain, responseMode);

        return new PresentationRequestResponseDTO(requestId, walletUrl, requestUri, clientId, expiresAt);
    }

    @Override
    public String buildPresentationRequest(String requestId, String tenantDomain) throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }

        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }

        // Mark the session failed and reject if the session is not active.
        if (session.getStatus() != VPSessionStatus.ACTIVE) {
            handleSessionFailed(requestId, tenantDomain, PresentationCoreErrorCode.VP_REQUEST_EXPIRED.getErrorType(),
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED.getDescription());
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED);
        }

        JWTClaimsSet claims = buildPresentationRequestClaims(session);
        return signWithTenantKey(claims, tenantDomain, tenantId);
    }

    /**
     * Signs the given JWT claims with the tenant's EC private key.
     *
     * <p>Loads the tenant's OAuth keystore, resolves the EC private key and signing certificate,
     * builds the JWS header with type {@code oauth-authz-req+jwt}, the certificate hash as {@code kid},
     * and the full chain as {@code x5c}, then signs with ES256.
     *
     * @param claims       JWT claims to sign.
     * @param tenantDomain tenant whose keystore is used for signing.
     * @param tenantId     numeric tenant ID used to obtain the keystore manager.
     * @return the compact-serialized signed JWS string.
     * @throws PresentationCoreException if key/cert loading or signing fails.
     */
    private String signWithTenantKey(JWTClaimsSet claims, String tenantDomain, int tenantId)
            throws PresentationCoreException {

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            KeyStore keyStore = IdentityKeyStoreResolver.getInstance()
                    .getKeyStore(tenantDomain, InboundProtocol.OAUTH);
            // Resolve the EC key alias registered for this tenant.
            String keyAlias = PresentationCoreUtil.resolveSigningKeyAlias(tenantDomain);
            // Load the EC private key using the tenant keystore password.
            ECPrivateKey ecKey = PresentationCoreUtil.loadEcPrivateKey(keyStore, keyAlias,
                    PresentationCoreUtil.resolveKeyPassword(keyStoreManager, tenantDomain));
            X509Certificate certificate = PresentationCoreUtil.resolveSigningCertificate(keyStore, keyAlias);
            Certificate[] certificateChain = keyStore.getCertificateChain(keyAlias);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(PresentationCoreConstants.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                    .keyID(PresentationCoreUtil.computeCertHash(certificate))
                    .x509CertChain(PresentationCoreUtil.buildX5cChain(certificateChain, certificate))
                    .build();
            JWSObject jws = new JWSObject(header, new Payload(claims.toJSONObject()));
            jws.sign(new ECDSASigner(ecKey));
            return jws.serialize();
        } catch (GeneralSecurityException | JOSEException | IdentityKeyStoreResolverException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_ERROR, e);
        }
    }

    /**
     * Builds the JWT claims set for the VP request.
     *
     * <p>Populates standard OAuth/OpenID4VP parameters from the session: issuer, audience,
     * {@code client_id}, {@code response_type}, {@code response_mode}, {@code response_uri},
     * {@code nonce}, {@code state}, and the DCQL query that describes the requested credentials.
     * When {@code direct_post.jwt} is configured, the ephemeral public key is included in
     * {@code client_metadata} so the wallet can perform ECDH-ES encryption.
     *
     * @param session active VP session containing all parameters for this VP request.
     * @return the assembled {@link JWTClaimsSet} ready to be signed.
     * @throws PresentationCoreServerException if the ephemeral public key cannot be parsed.
     */
    private static JWTClaimsSet buildPresentationRequestClaims(VPSession session) throws
        PresentationCoreServerException{

        String clientId = session.getClientId();
        return new JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience(Constants.Protocol.REQUEST_AUDIENCE)
                .claim(Constants.RequestParams.CLIENT_ID, clientId)
                .claim(Constants.JWTClaims.CLIENT_ID_SCHEME, session.getClientIdScheme())
                .claim(Constants.RequestParams.RESPONSE_TYPE, Constants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                .claim(Constants.RequestParams.RESPONSE_MODE, session.getResponseMode())
                .claim(Constants.RequestParams.RESPONSE_URI, session.getResponseUri())
                .claim(Constants.RequestParams.NONCE, session.getNonce())
                .claim(Constants.RequestParams.STATE, session.getRequestId())
                .issueTime(new Date())
                .expirationTime(new Date(session.getExpiresAt()))
                .jwtID(UUID.randomUUID().toString())
                .claim(Constants.JWTClaims.DCQL_QUERY,
                        DcqlUtil.buildDcqlQuery(session.getPresentationDefinition()))
                .claim(PresentationCoreConstants.CLAIM_CLIENT_METADATA,
                        DcqlUtil.buildClientMetadata(clientId, PresentationCoreUtil.resolveEphemeralPublicKey(session)))
                .build();
    }

    /**
     * Returns the live {@link VPSession} for the given request ID, or {@code null}
     * if the session has expired or was never created.
     *
     * @param requestId Request ID returned by {@code initiate}.
     * @return The cached session, or {@code null} if absent or expired.
     * @throws PresentationCoreServerException If the database read or secret decryption fails.
     */
    @Override
    public VPSession getPresentationSession(String requestId, String tenantDomain) throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        if (System.currentTimeMillis() > session.getExpiresAt()) {
            VPSessionCache.getInstance().clearCacheEntry(
                    new VPSessionCacheKey(requestId), tenantId);
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED);
        }
        return session;
    }

    private VPSession getSessionFromCache(String requestId, int tenantId) {

        VPSessionCacheEntry entry = VPSessionCache.getInstance().getValueFromCache(
                new VPSessionCacheKey(requestId), tenantId);
        return entry != null ? entry.getSession() : null;
    }

    private void validateResponseMode(String configuredResponseMode, boolean encryptedResponseExpected)
            throws PresentationCoreClientException {

        boolean isEncryptedResponseMode = PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT
                .equals(configuredResponseMode);
        if (isEncryptedResponseMode != encryptedResponseExpected) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.RESPONSE_MODE_MISMATCH);
        }
    }

    @Override
    public PresentationSubmissionDTO parsePresentationSubmission(Map<String, List<String>> formParams,
                                                                 String tenantDomain)
            throws PresentationCoreException {

        // If `response` parameter exists: a direct_post.jwt (JWE-encrypted) response.
        String responseParam = PresentationCoreUtil.
                extractFirstFormParam(formParams, Constants.ResponseParams.RESPONSE);
        if (StringUtils.isNotBlank(responseParam)) {
            return parseDirectPostJwt(responseParam, tenantDomain);
        }
        return parseDirectPost(formParams, tenantDomain);
    }

    private PresentationSubmissionDTO parseDirectPostJwt(String responseParam, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String requestId = null;
        try {
            JWEObject jweObject = JWEObject.parse(responseParam);
            requestId = jweObject.getHeader().getKeyID();
            if (StringUtils.isBlank(requestId)) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            VPSession session = getSessionFromCache(requestId, tenantId);
            if (session == null || StringUtils.isBlank(session.getEphemeralPrivateKeyJwk())) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            validateResponseMode(session.getResponseMode(), true);
            JWTClaimsSet claims = PresentationCoreUtil.decryptJweResponse(
                    jweObject, session.getEphemeralPrivateKeyJwk());

            String error = claims.getStringClaim(Constants.ResponseParams.ERROR);
            if (StringUtils.isNotBlank(error)) {
                return PresentationSubmissionDTO.builder()
                        .requestId(requestId)
                        .error(error)
                        .errorDescription(claims.getStringClaim(Constants.ResponseParams.ERROR_DESCRIPTION))
                        .build();
                }

            Map<String, Object> vpTokenMap = claims.getJSONObjectClaim(Constants.ResponseParams.VP_TOKEN);
            return PresentationSubmissionDTO.builder()
                    .requestId(requestId)
                    .credentialTokens(vpTokenMap != null ? PresentationCoreUtil.flattenVpTokenMap(vpTokenMap) : null)
                    .build();

        } catch (PresentationCoreException e) {
            handleSessionFailed(requestId, tenantDomain, e.getErrorType(), e.getDescription());
            throw e;
        } catch (ParseException | JOSEException e) {
            handleSessionFailed(requestId, tenantDomain,
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR.getErrorType(),
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR.getDescription());
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR, e);
        }
    }

    private PresentationSubmissionDTO parseDirectPost(Map<String, List<String>> formParams, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String requestId = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.STATE);
        String error = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.ERROR);

        if (StringUtils.isNotBlank(error)) {
            return PresentationSubmissionDTO.builder()
                    .requestId(requestId)
                    .error(error)
                    .errorDescription(PresentationCoreUtil.extractFirstFormParam(
                            formParams, Constants.ResponseParams.ERROR_DESCRIPTION))
                    .build();
        }

        if (StringUtils.isNotBlank(requestId)) {
            VPSession session = getSessionFromCache(requestId, tenantId);
            if (session != null) {
                validateResponseMode(session.getResponseMode(), false);
            }
        }

        String vpToken = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.VP_TOKEN);
        try {
            Map<String, Object> rawMap = GSON.fromJson(vpToken, VP_TOKEN_TYPE);
            return PresentationSubmissionDTO.builder()
                    .requestId(requestId)
                    .credentialTokens(PresentationCoreUtil.flattenVpTokenMap(rawMap))
                    .build();
        } catch (JsonSyntaxException e) {
            handleSessionFailed(requestId, tenantDomain,
                    PresentationCoreErrorCode.INVALID_VP_TOKEN.getErrorType(),
                    PresentationCoreErrorCode.INVALID_VP_TOKEN.getDescription());
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }
    }

    @Override
    public VerificationRequestDTO buildVerificationRequest(PresentationSubmissionDTO submission, String tenantDomain)
            throws PresentationCoreException {

        String requestId = submission.getRequestId();

        if (StringUtils.isBlank(requestId)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        if (submission.getCredentialTokens() == null || submission.getCredentialTokens().isEmpty()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        if (session.getStatus() != VPSessionStatus.ACTIVE) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }

        PresentationDefinition definition = session.getPresentationDefinition();
        if (CollectionUtils.isEmpty(definition.getCredentials())) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        Credential credential = definition.getCredentials().getFirst();
        String credentialToken = submission.getCredentialTokens().get(credential.getIdentifier());
        if (StringUtils.isBlank(credentialToken)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }

        return new VerificationRequestDTO(credentialToken, credential,
                session.getNonce(), session.getClientId());
    }

    @Override
    public void handleSessionVerified(String requestId, VerificationResponseDTO verificationResponse, String tenantDomain)
            throws PresentationCoreException {
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            LOG.warn("Session not found when finalizing as verified: " + requestId);
            return;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        session.setVerificationResponse(verificationResponse);
        session.setStatus(VPSessionStatus.VERIFIED);
        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), tenantId);
        AUDIT_LOGGER.logVPCredentialVerified(requestId,
                verificationResponse != null ? verificationResponse.getCredentialId() : null,
                session.getTenantDomain());
    }

    @Override
    public void handleSessionFailed(String requestId, String errorType, String errorDescription, String tenantDomain)
            throws PresentationCoreException {

        if (StringUtils.isBlank(requestId)) {
            return;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            LOG.warn("Session not found when finalizing as failed: " + requestId);
            return;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        if (session.getStatus() == VPSessionStatus.VERIFIED || session.getStatus() == VPSessionStatus.FAILED) {
            return;
        }
        session.setStatus(VPSessionStatus.FAILED);
        session.setErrorType(errorType);
        session.setErrorDescription(errorDescription);
        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), tenantId);
        AUDIT_LOGGER.logVPCredentialVerificationFailed(requestId, errorType, errorDescription,
                session.getTenantDomain());
    }

    @Override
    public VerificationSessionStatusDTO getPresentationSessionStatus(String requestId, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            return null;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        VPSessionStatus status = session.getStatus();
        VerificationSessionStatusDTO verificationSessionStatus = new VerificationSessionStatusDTO();
        verificationSessionStatus.setRequestId(session.getRequestId());
        verificationSessionStatus.setStatus(status);
        verificationSessionStatus.setExpiresAt(session.getExpiresAt());
        verificationSessionStatus.setErrorType(session.getErrorType());
        return verificationSessionStatus;
    }

    @Override
    public VerificationSessionRespDTO getPresentationSessionResult(String requestId, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            return null;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        VPSessionStatus status = session.getStatus();
        // Block callers from consuming the result endpoint while verification is still in progress.
        if (status == VPSessionStatus.ACTIVE) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_SESSION_PENDING);
        }
        VerificationSessionRespDTO verificationSessionResponse = new VerificationSessionRespDTO();
        verificationSessionResponse.setRequestId(requestId);
        verificationSessionResponse.setStatus(status);
        verificationSessionResponse.setVerificationResponse(session.getVerificationResponse());
        verificationSessionResponse.setErrorType(session.getErrorType());
        verificationSessionResponse.setErrorDescription(session.getErrorDescription());

        return verificationSessionResponse;
    }

    /**
     * Generates a one-time EC P-256 key pair for ECDH encryption of the wallet's VP token response.
     *
     * <p>The {@code requestId} is set as the key ID ({@code kid}) so the server can look up
     * the matching private key from the session when the encrypted response arrives.
     *
     * @param requestId session request ID used as the key's {@code kid}.
     * @return the generated private key serialized as a JWK JSON string.
     * @throws PresentationCoreServerException if key generation fails.
     */
    private String generateEphemeralKey(String requestId) throws PresentationCoreServerException {

        try {
            return new ECKeyGenerator(Curve.P_256).keyID(requestId).generate().toJSONString();
        } catch (JOSEException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.EPHEMERAL_KEY_ERROR, e);
        }
    }
}
