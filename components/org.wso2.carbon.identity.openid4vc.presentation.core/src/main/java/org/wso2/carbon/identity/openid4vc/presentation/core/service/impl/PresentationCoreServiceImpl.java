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
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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
        String baseUrl = PresentationCoreUtil.buildServerBaseUrl();
//        TODO: use private methods
//        Use a util method to build the response uri
        String responseUri = baseUrl + PresentationCoreConstants.RESPONSE_URI_ENDPOINT;
        VPTenantConfig vptenantConfig = PresentationCoreDataHolder.getInstance()
                .getVpConfigService().getVPConfig(tenantDomain);
        String scheme = StringUtils.defaultIfBlank(
                vptenantConfig.getClientIdScheme(), Constants.DEFAULT_CLIENT_ID_SCHEME);
        String responseMode = StringUtils.defaultIfBlank(
                vptenantConfig.getResponseMode(), PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT);
        String clientId = PresentationCoreUtil.buildClientId(scheme, tenantDomain);

        String ephemeralPrivateKeyJwk = null;
        if (PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT.equals(responseMode)) {
            try {
                ephemeralPrivateKeyJwk = new ECKeyGenerator(Curve.P_256).keyID(requestId).generate().toJSONString();
            } catch (JOSEException e) {
                throw PresentationCoreExceptionHandler.handleServerException(
                        PresentationCoreErrorCode.EPHEMERAL_KEY_ERROR, e);
            }
        }
//       TODO: use a build
        String requestUri = baseUrl + PresentationCoreConstants.REQUEST_URI_ENDPOINT + requestId;
        String walletUrl = Constants.Protocol.OPENID4VP_SCHEME + "?"
                + Constants.RequestParams.CLIENT_ID + "=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&" + Constants.RequestParams.REQUEST_URI + "="
                + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

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
                new VPSessionCacheEntry(session), MultitenantConstants.SUPER_TENANT_ID);
        AUDIT_LOGGER.logVPSessionInitiated(requestId, presentationDefinition, tenantDomain, responseMode);

        return new PresentationRequestResponseDTO(requestId, walletUrl, requestUri, clientId, expiresAt);
    }

    @Override
    public String buildPresentationRequest(String requestId) throws PresentationCoreException {

        VPSession session = getSessionFromCache(requestId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }

        String clientIdScheme = StringUtils.defaultIfBlank(session.getClientIdScheme(), Constants.DEFAULT_CLIENT_ID_SCHEME);
        String tenantDomain = session.getTenantDomain();
        int tenantId = session.getTenantId();
        ECKey ephemeralPublicKey = PresentationCoreUtil.resolveEphemeralPublicKey(session);

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            KeyStore keyStore = IdentityKeyStoreResolver.getInstance().getKeyStore(tenantDomain, InboundProtocol.OAUTH);
            String keyAlias = PresentationCoreUtil.resolveSigningKeyAlias(tenantDomain);

            ECPrivateKey ecKey = PresentationCoreUtil.loadEcPrivateKey(keyStore, keyAlias,
                    PresentationCoreUtil.resolveKeyPassword(keyStoreManager, tenantDomain));

            Certificate[] certificateChain = keyStore.getCertificateChain(keyAlias);
            X509Certificate certificate = certificateChain != null && certificateChain.length > 0
                    ? (X509Certificate) certificateChain[0] : (X509Certificate) keyStore.getCertificate(keyAlias);
            if (certificate == null) {
                throw PresentationCoreExceptionHandler.handleServerException(
                        PresentationCoreErrorCode.SIGNING_CERTIFICATE_ERROR, null);
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(PresentationCoreConstants.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                    .keyID(PresentationCoreUtil.computeCertHash(certificate))
                    .x509CertChain(PresentationCoreUtil.buildX5cChain(certificateChain, certificate))
                    .build();
            JWTClaimsSet claims = buildPresentationRequestClaims(session, requestId, clientIdScheme, ephemeralPublicKey);

            JWSObject jws = new JWSObject(header, new Payload(claims.toJSONObject()));
            jws.sign(new ECDSASigner(ecKey));
            return jws.serialize();

        } catch (GeneralSecurityException | JOSEException | IdentityKeyStoreResolverException e) {
            LOG.error("Error building auth request JWT for tenant=" + tenantDomain, e);
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_ERROR, e);
        }
    }

    private static JWTClaimsSet buildPresentationRequestClaims(VPSession session, String requestId, String scheme,
                                                               ECKey ephemeralPublicKey) {

        String clientId = session.getClientId();
        return new JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience(Constants.Protocol.REQUEST_AUDIENCE)
                .claim(Constants.RequestParams.CLIENT_ID, clientId)
                .claim(Constants.JWTClaims.CLIENT_ID_SCHEME, scheme)
                .claim(Constants.RequestParams.RESPONSE_TYPE, Constants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                .claim(Constants.RequestParams.RESPONSE_MODE, session.getResponseMode())
                .claim(Constants.RequestParams.RESPONSE_URI, session.getResponseUri())
                .claim(Constants.RequestParams.NONCE, session.getNonce())
                .claim(Constants.RequestParams.STATE, requestId)
                .issueTime(new Date())
                .expirationTime(new Date(session.getExpiresAt()))
                .jwtID(UUID.randomUUID().toString())
                .claim(Constants.JWTClaims.DCQL_QUERY,
                        DcqlUtil.buildDcqlQuery(session.getPresentationDefinition()))
                .claim(PresentationCoreConstants.CLAIM_CLIENT_METADATA,
                        DcqlUtil.buildClientMetadata(clientId, ephemeralPublicKey))
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
    public VPSession getPresentationSession(String requestId) throws PresentationCoreException {

        VPSession session = getSessionFromCache(requestId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        if (System.currentTimeMillis() > session.getExpiresAt()) {
            VPSessionCache.getInstance().clearCacheEntry(
                    new VPSessionCacheKey(requestId), MultitenantConstants.SUPER_TENANT_ID);
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED);
        }
        return session;
    }

    private VPSession getSessionFromCache(String requestId) {

        VPSessionCacheEntry entry = VPSessionCache.getInstance().getValueFromCache(
                new VPSessionCacheKey(requestId), MultitenantConstants.SUPER_TENANT_ID);
        return entry != null ? entry.getSession() : null;
    }


    private void validateResponseMode(VPSession session, String requestId, boolean encryptedResponseExpected)
            throws PresentationCoreClientException {

        boolean isEncryptedResponseMode = PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT
                .equals(session.getResponseMode());
        if (isEncryptedResponseMode != encryptedResponseExpected) {
            handleSessionFailed(requestId,
                    PresentationCoreErrorCode.RESPONSE_MODE_MISMATCH.getErrorType(),
                    PresentationCoreErrorCode.RESPONSE_MODE_MISMATCH.getDescription());
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.RESPONSE_MODE_MISMATCH);
        }
    }

    @Override
    public PresentationSubmissionDTO parsePresentationSubmission(Map<String, List<String>> formParams)
            throws PresentationCoreException {

        String responseParam = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.RESPONSE);
        if (StringUtils.isNotBlank(responseParam)) {
            return parseDirectPostJwt(responseParam);
        }
        return parseDirectPost(formParams);
    }

    private PresentationSubmissionDTO parseDirectPostJwt(String responseParam) throws PresentationCoreException {

        String requestId = null;
        try {
            JWEObject jweObject = JWEObject.parse(responseParam);
            requestId = jweObject.getHeader().getKeyID();
            if (StringUtils.isBlank(requestId)) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            VPSession session = getSessionFromCache(requestId);
            if (session == null || StringUtils.isBlank(session.getEphemeralPrivateKeyJwk())) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            validateResponseMode(session, requestId, true);

            jweObject.decrypt(new ECDHDecrypter(ECKey.parse(session.getEphemeralPrivateKeyJwk())));

            SignedJWT innerJwt = jweObject.getPayload().toSignedJWT();
            JWTClaimsSet claims = (innerJwt != null)
                    ? innerJwt.getJWTClaimsSet()
                    : JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());

            String state = claims.getStringClaim(Constants.ResponseParams.STATE);
            String resolvedRequestId = state != null ? state : requestId;
            String error = claims.getStringClaim(Constants.ResponseParams.ERROR);

            if (StringUtils.isNotBlank(error)) {
                return PresentationSubmissionDTO.builder()
                        .requestId(resolvedRequestId)
                        .error(error)
                        .errorDescription(claims.getStringClaim(Constants.ResponseParams.ERROR_DESCRIPTION))
                        .build();
            }

            Map<String, Object> vpTokenMap = claims.getJSONObjectClaim(Constants.ResponseParams.VP_TOKEN);
            return PresentationSubmissionDTO.builder()
                    .requestId(resolvedRequestId)
                    .credentialTokens(vpTokenMap != null ? PresentationCoreUtil.flattenVpTokenMap(vpTokenMap) : null)
                    .build();

        } catch (ParseException | JOSEException e) {
            handleSessionFailed(requestId,
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR.getErrorType(),
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR.getDescription());
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR, e);
        }
    }

    private PresentationSubmissionDTO parseDirectPost(Map<String, List<String>> formParams)
            throws PresentationCoreException {

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
            VPSession session = getSessionFromCache(requestId);
            if (session != null) {
                validateResponseMode(session, requestId, false);
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
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }
    }

    @Override
    public VerificationRequestDTO buildVerificationRequest(PresentationSubmissionDTO submission)
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

        VPSession session = getSessionFromCache(requestId);
        if (session == null) {
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
    public void handleSessionVerified(String requestId, VerificationResponseDTO verificationResponse) {

            VPSession session = getSessionFromCache(requestId);
            if (session == null) {
                LOG.warn("Session not found when finalizing as verified: " + requestId);
                return;
            }
            session.setVerificationResponse(verificationResponse);
            session.setStatus(VPSessionStatus.VERIFIED);
            VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                    new VPSessionCacheEntry(session), MultitenantConstants.SUPER_TENANT_ID);
            AUDIT_LOGGER.logVPCredentialVerified(requestId,
                    verificationResponse != null ? verificationResponse.getCredentialId() : null,
                    session.getTenantDomain());
    }

    @Override
    public void handleSessionFailed(String requestId, String errorType, String errorDescription) {

        if (StringUtils.isBlank(requestId)) {
            return;
        }
        VPSession session = getSessionFromCache(requestId);
        if (session == null) {
            LOG.warn("Session not found when finalizing as failed: " + requestId);
            return;
        }
        if (session.getStatus() == VPSessionStatus.VERIFIED || session.getStatus() == VPSessionStatus.FAILED) {
            return;
        }
        session.setStatus(VPSessionStatus.FAILED);
        session.setErrorType(errorType);
        session.setErrorDescription(errorDescription);
        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), MultitenantConstants.SUPER_TENANT_ID);
        AUDIT_LOGGER.logVPCredentialVerificationFailed(requestId, errorType, errorDescription,
                session.getTenantDomain());
    }

    @Override
    public VerificationSessionRespDTO getPresentationSessionStatus(String requestId) {

        VPSession session = getSessionFromCache(requestId);
        if (session == null) {
            return null;
        }
        VPSessionStatus status = session.getStatus();
        VerificationSessionRespDTO verificationSessionResponse = new VerificationSessionRespDTO();
        verificationSessionResponse.setStatus(status);
        verificationSessionResponse.setVerificationResponse(session.getVerificationResponse());
        verificationSessionResponse.setErrorType(session.getErrorType());
        verificationSessionResponse.setErrorDescription(session.getErrorDescription());
        verificationSessionResponse.setExpiresAt(session.getExpiresAt());
        if (status == VPSessionStatus.VERIFIED || status == VPSessionStatus.FAILED) {
            VPSessionCache.getInstance().clearCacheEntry(
                    new VPSessionCacheKey(requestId), MultitenantConstants.SUPER_TENANT_ID);
        }
        return verificationSessionResponse;
    }
}
