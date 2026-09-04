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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPAuthorizationRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowInitiationResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.WalletSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.AuthorizationRequestBuilder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.DcqlQueryMapper;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.service.PresentationDefinitionService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Map;
import java.util.UUID;

/**
 * Session lifecycle manager for VP authorization flows.
 *
 * <p>Responsible for initiating, retrieving, and removing VP flow sessions.
 * JWT construction and signing is delegated to {@link AuthorizationRequestBuilder}.
 */
public class VPFlowServiceImpl implements VPFlowService {

    private static final Log LOG = LogFactory.getLog(VPFlowServiceImpl.class);

    /**
     * Initiates a VP flow session with a configurable timeout.
     *
     * @param presentationDefinitionId ID of the presentation definition describing required credentials.
     * @param tenantDomain             Tenant domain under which the flow runs.
     * @param timeoutMs                Session TTL in milliseconds from now.
     * @return {@link VPFlowInitiationResult} containing the request ID, wallet URL, and expiry time.
     * @throws VPAuthenticatorException If any argument is blank or session initialisation fails.
     */
    @Override
    public VPFlowInitiationResult initiate(String presentationDefinitionId, String tenantDomain,
            long timeoutMs) throws VPAuthenticatorException {

        return initiateInternal(UUID.randomUUID().toString(), presentationDefinitionId, tenantDomain, timeoutMs);
    }

    /**
     * Core flow initiation logic shared by both public {@code initiate} overloads.
     *
     * <p>Resolves tenant configuration, generates a nonce and an ephemeral EC key when
     * {@code direct_post.jwt} response mode is active, builds and caches the
     * {@link VPFlowSession}, then returns the initiation result.
     *
     * @param requestId                Unique ID for this VP request.
     * @param presentationDefinitionId ID of the presentation definition.
     * @param tenantDomain             Tenant domain.
     * @param timeoutMs                Session TTL in milliseconds from now.
     * @return {@link VPFlowInitiationResult} with wallet URL and expiry.
     * @throws VPAuthenticatorException On blank inputs, ephemeral key generation failure,
     *                                  or base URL resolution error.
     */
    private VPFlowInitiationResult initiateInternal(String requestId, String presentationDefinitionId,
            String tenantDomain, long timeoutMs)
            throws VPAuthenticatorException {

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "presentationDefinitionId is required.");
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "tenantDomain is required.");
        }

        String nonce = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + timeoutMs;

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        PresentationDefinition presentationDefinition;
        try {
            presentationDefinition = getPresentationDefinitionService()
                    .getPresentationDefinitionById(presentationDefinitionId, tenantId);
        } catch (PresentationManagementException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to load presentation definition: " + presentationDefinitionId, e);
        }
        if (presentationDefinition == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Presentation definition not found: " + presentationDefinitionId);
        }
        DcqlQuery dcqlQuery = DcqlQueryMapper.from(presentationDefinition);

        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();
        String responseUri = baseUrl + Constants.RESPONSE_URI_ENDPOINT;
        VPConfigService.TenantConfig tenantConfig = VPAuthenticatorUtil.loadTenantConfig(tenantDomain);
        String scheme = StringUtils.defaultIfBlank(
                tenantConfig.getClientIdScheme(), VPConstants.DEFAULT_CLIENT_ID_SCHEME);
        String responseMode = StringUtils.defaultIfBlank(
                tenantConfig.getResponseMode(), Constants.RESPONSE_MODE_DIRECT_POST_JWT);
        String clientId = VPAuthenticatorUtil.resolveClientIdForScheme(scheme, baseUrl, tenantDomain);

        String ephemeralPrivateKeyJwk = null;
        if (Constants.RESPONSE_MODE_DIRECT_POST_JWT.equals(responseMode)) {
            try {
                ephemeralPrivateKeyJwk = new ECKeyGenerator(Curve.P_256).keyID(requestId).generate().toJSONString();
            } catch (JOSEException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to generate ephemeral key for VP flow session.", e);
            }
        }

        String requestUri = baseUrl + Constants.REQUEST_URI_ENDPOINT + requestId;
        String walletUrl = VPConstants.Protocol.OPENID4VP_SCHEME + "?"
                + VPConstants.RequestParams.CLIENT_ID + "=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&" + VPConstants.RequestParams.REQUEST_URI + "="
                + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

        VPFlowSession session = new VPFlowSession.Builder()
                .dcqlQuery(dcqlQuery)
                .tenantDomain(tenantDomain)
                .tenantId(tenantId)
                .status(VPFlowStatus.ACTIVE)
                .nonce(nonce)
                .ephemeralPrivateKeyJwk(ephemeralPrivateKeyJwk)
                .expiresAt(expiresAt)
                .clientId(clientId)
                .clientIdScheme(scheme)
                .responseUri(responseUri)
                .responseMode(responseMode)
                .walletUrl(walletUrl)
                .build();

        VPSessionCache.getInstance().put(requestId, session);

        return new VPFlowInitiationResult(requestId, walletUrl, requestUri, clientId, expiresAt);
    }

    @Override
    public String createAuthorizationRequestJwt(String requestId) throws VPAuthenticatorException {

        VPFlowSession session = VPSessionCache.getInstance().get(requestId);
        if (session == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                    "VP flow session not found: " + requestId);
        }

        ECKey ephemeralPublicKey = null;
        if (StringUtils.isNotBlank(session.getEphemeralPrivateKeyJwk())) {
            try {
                ephemeralPublicKey = ECKey.parse(session.getEphemeralPrivateKeyJwk()).toPublicJWK();
            } catch (ParseException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to parse ephemeral key from VP flow session.", e);
            }
        }

        VPAuthorizationRequest vpRequest = new VPAuthorizationRequest.Builder()
                .requestId(requestId)
                .clientId(session.getClientId())
                .nonce(session.getNonce())
                .responseUri(session.getResponseUri())
                .responseMode(session.getResponseMode())
                .status(VPFlowStatus.ACTIVE)
                .expiresAt(session.getExpiresAt())
                .build();

        return AuthorizationRequestBuilder.sign(
                vpRequest, session.getDcqlQuery(),
                session.getTenantDomain(), session.getTenantId(),
                ephemeralPublicKey, session.getClientIdScheme());
    }

    /**
     * Returns the live {@link VPFlowSession} for the given request ID, or {@code null}
     * if the session has expired or was never created.
     *
     * @param requestId Request ID returned by {@code initiate}.
     * @return The cached session, or {@code null} if absent or expired.
     * @throws VPAuthenticatorServerException If the database read or secret decryption fails.
     */
    @Override
    public VPFlowSession getSession(String requestId) throws VPAuthenticatorServerException {

        return VPSessionCache.getInstance().get(requestId);
    }

    /**
     * Removes the VP flow session from the distributed cache, releasing any stored PII.
     *
     * @param requestId Request ID of the session to remove.
     */
    @Override
    public void removeSession(String requestId) {

        VPSessionCache.getInstance().remove(requestId);
    }

    @Override
    public void failSession(String requestId, String reason) {

        if (StringUtils.isBlank(requestId)) {
            return;
        }
        try {
            VPFlowSession session = VPSessionCache.getInstance().get(requestId);
            if (session == null) {
                return;
            }
            if (session.getStatus() == VPFlowStatus.VERIFIED || session.getStatus() == VPFlowStatus.FAILED) {
                return;
            }
            failSession(session, requestId, reason);
        } catch (Exception e) {
            LOG.warn("Failed to mark VP session as FAILED for requestId: " + requestId, e);
        }
    }

    @Override
    public void processWalletResponse(WalletSubmission submission) throws VPAuthenticatorException {

        if (submission.getRawJwe() != null) {
            decryptJweIntoSubmission(submission);
        }

        String requestId = submission.getRequestId();

        // Handle wallet-side errors: record the failure and return normally —
        // the server always responds 200 OK to the wallet even when the wallet reports an error.
        if (StringUtils.isNotBlank(submission.getError())) {
            if (StringUtils.isNotBlank(requestId)) {
                VPFlowSession errorSession = VPSessionCache.getInstance().get(requestId);
                if (errorSession != null) {
                    String reason = StringUtils.isNotBlank(submission.getErrorDescription())
                            ? submission.getErrorDescription() : submission.getError();
                    errorSession.setStatus(VPFlowStatus.FAILED);
                    errorSession.setFailureReason(reason);
                    VPSessionCache.getInstance().put(requestId, errorSession);
                }
            }
            return;
        }

        if (StringUtils.isBlank(requestId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Missing state parameter.");
        }
        if (submission.getCredentialTokens() == null || submission.getCredentialTokens().isEmpty()) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Missing vp_token.");
        }

        VPFlowSession session = VPSessionCache.getInstance().get(requestId);
        if (session == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Invalid state parameter.");
        }
        if (System.currentTimeMillis() > session.getExpiresAt()) {
            VPSessionCache.getInstance().remove(requestId);
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                    "VP session has expired.");
        }
        if (session.getStatus() != VPFlowStatus.ACTIVE) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "VP session is no longer active.");
        }

        boolean expectEncrypted = Constants.RESPONSE_MODE_DIRECT_POST_JWT.equals(session.getResponseMode());
        if (expectEncrypted && !submission.isEncrypted()) {
            failSession(session, requestId, "Response mode mismatch.");
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Response mode mismatch: direct_post.jwt was configured but wallet sent an unencrypted response.");
        }
        if (!expectEncrypted && submission.isEncrypted()) {
            failSession(session, requestId, "Response mode mismatch.");
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Response mode mismatch: direct_post was configured but wallet sent an encrypted JWE response.");
        }

        try {
            VerificationResult result = VPDataHolder.getVerificationService()
                    .verify(session.getDcqlQuery(), session.getTenantId(),
                            submission.getCredentialTokens(), session.getNonce(), session.getClientId());

            if (!result.isVerified()) {
                String errorMsg = !result.getErrors().isEmpty()
                        ? String.join(", ", result.getErrors()) : "VP verification failed.";
                failSession(session, requestId, errorMsg);
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VERIFICATION_FAILED, errorMsg);
            }

            session.setVerificationResult(result);
            session.setStatus(VPFlowStatus.VERIFIED);
            VPSessionCache.getInstance().put(requestId, session);

        } catch (VerificationException e) {
            failSession(session, requestId, e.getMessage());
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VERIFICATION_FAILED, e.getMessage());
        }
    }

    private static void failSession(VPFlowSession session, String requestId, String reason)
            throws VPAuthenticatorServerException {

        session.setStatus(VPFlowStatus.FAILED);
        session.setFailureReason(reason);
        VPSessionCache.getInstance().put(requestId, session);
    }

    /**
     * Decrypts a {@code direct_post.jwt} JWE and populates {@code submission} with the extracted claims.
     * The JWE kid identifies the session whose ephemeral private key is used for decryption.
     * On decryption failure the session is marked FAILED before throwing, so the polling client
     * sees an immediate terminal state rather than waiting for session expiry.
     *
     * @param submission the submission carrying a raw JWE in {@link WalletSubmission#getRawJwe()}
     * @throws VPAuthenticatorException on JWE header parse failure, missing ephemeral key,
     *                                  decryption error, or inner JWT claim parsing failure
     */
    private void decryptJweIntoSubmission(WalletSubmission submission) throws VPAuthenticatorException {

        String jweCompact = submission.getRawJwe();
        String requestId = null;
        try {
            JWEObject jweObject = JWEObject.parse(jweCompact);
            requestId = jweObject.getHeader().getKeyID();
            if (StringUtils.isBlank(requestId)) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "direct_post.jwt: missing kid in JWE header.");
            }

            VPFlowSession session = VPSessionCache.getInstance().get(requestId);
            if (session == null || StringUtils.isBlank(session.getEphemeralPrivateKeyJwk())) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "direct_post.jwt: no ephemeral key found for state: " + requestId);
            }

            jweObject.decrypt(new ECDHDecrypter(ECKey.parse(session.getEphemeralPrivateKeyJwk())));

            // Some wallets encrypt plain JSON claims directly without an inner signed JWT.
            SignedJWT innerJwt = jweObject.getPayload().toSignedJWT();
            JWTClaimsSet claims = (innerJwt != null)
                    ? innerJwt.getJWTClaimsSet()
                    : JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());

            Map<String, Object> vpTokenMap = claims.getJSONObjectClaim(VPConstants.ResponseParams.VP_TOKEN);
            if (vpTokenMap != null) {
                submission.setCredentialTokens(VPAuthenticatorUtil.flattenVpTokenMap(vpTokenMap));
            }
            String state = claims.getStringClaim(VPConstants.ResponseParams.STATE);
            submission.setRequestId(state != null ? state : requestId);
            submission.setError(claims.getStringClaim(VPConstants.ResponseParams.ERROR));
            submission.setErrorDescription(claims.getStringClaim(VPConstants.ResponseParams.ERROR_DESCRIPTION));
            submission.setEncrypted(true);

        } catch (ParseException | JOSEException e) {
            if (requestId != null) {
                VPFlowSession failTarget = VPSessionCache.getInstance().get(requestId);
                if (failTarget != null) {
                    failSession(failTarget, requestId, "Failed to decrypt wallet response.");
                }
            }
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to decrypt or parse direct_post.jwt JWE response.", e);
        }
    }

    /**
     * Returns the {@link PresentationDefinitionService} from the OSGi service holder,
     * throwing a server exception if it has not yet been bound.
     *
     * @return Non-null presentation definition service.
     * @throws VPAuthenticatorException If the service is unavailable.
     */
    private PresentationDefinitionService getPresentationDefinitionService() throws VPAuthenticatorException {

        PresentationDefinitionService service = VPDataHolder.getPresentationDefinitionService();
        if (service == null) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Presentation definition service is not initialized.");
        }
        return service;
    }
}
