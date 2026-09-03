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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.AuthorizationRequestBuilder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.DcqlQueryMapper;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
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

        VPFlowSession session = new VPFlowSession.Builder()
                .requestId(requestId)
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
                .build();

        String requestUri = baseUrl + Constants.REQUEST_URI_ENDPOINT + requestId;
        String walletUrl = VPConstants.Protocol.OPENID4VP_SCHEME + "?"
                + VPConstants.RequestParams.CLIENT_ID + "=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&" + VPConstants.RequestParams.REQUEST_URI + "=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

        session.setWalletUrl(walletUrl);
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
