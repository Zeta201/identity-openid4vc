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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowInitiationResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationVerificationResult;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.CONTEXT_VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.DISPLAY_ORDER_PRESENTATION_DEFINITION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.DISPLAY_ORDER_TIMEOUT;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PARAM_STATUS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PARAM_VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_PRESENTATION_DEFINITION_ID_DESC;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_PRESENTATION_DEFINITION_ID_DISPLAY;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_TIMEOUT_DEFAULT_VALUE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_TIMEOUT_SECONDS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_TIMEOUT_SECONDS_DESC;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.PROP_TIMEOUT_SECONDS_DISPLAY;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.STATUS_FAILED;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.STATUS_SUCCESS;


/**
 * OpenID for Verifiable Presentations (OpenID4VP) authenticator for WSO2 Identity Server.
 *
 * <p>This authenticator implements the OpenID for Verifiable Presentations (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a digital wallet.</p>
 */
public class VPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(VPAuthenticator.class);

    private static final String WALLET_LOGIN_PAGE = "/authenticationendpoint/wallet_login.jsp";
    private static final String PARAM_SESSION_DATA_KEY = "sessionDataKey";

    private static final String PARAM_REQUEST_ID = "requestId";
    private static final String PARAM_WALLET_URL = "walletUrl";
    private static final String PARAM_TENANT_DOMAIN = "tenantDomain";
    private static final String PARAM_ORG_ID = "orgId";
    private static final String PARAM_ROOT_TENANT_DOMAIN = "rootTenantDomain";
    private static final String PARAM_SESSION_TTL_MS = "sessionTtlMs";

    /**
     * Returns the unique internal name of this authenticator, used by WSO2 IS
     * to identify and configure it in the authentication pipeline.
     *
     * @return authenticator name string.
     */
    @Override
    public String getName() {

        return AUTHENTICATOR_NAME;
    }

    /**
     * Returns the human-readable display name shown in the WSO2 IS management console
     * when configuring federated authenticators for an application.
     *
     * @return friendly name string.
     */
    @Override
    public String getFriendlyName() {

        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Initiate the authentication request to the wallet.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @throws AuthenticationFailedException If request initiation fails.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(VPConstants.ConfigKeys.FEATURE_ENABLED))) {
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.FEATURE_DISABLED.getCode(),
                    VPAuthenticatorErrorCode.FEATURE_DISABLED.getMessage());
        }

        try {
            String organizationId = VPAuthenticatorUtil.resolveOrganizationId();
            String tenantDomain = VPAuthenticatorUtil.resolveTenantDomain();

            String presentationDefinitionId = MapUtils.getString(
                    context.getAuthenticatorProperties(), PROP_PRESENTATION_DEFINITION_ID);

            long timeoutMs = VPAuthenticatorUtil.resolveTimeoutMs(context.getAuthenticatorProperties());

            VPFlowInitiationResult initiationResult = VPDataHolder.getVPFlowService()
                    .initiate(presentationDefinitionId, tenantDomain, timeoutMs);

            context.setProperty(CONTEXT_VP_REQUEST_ID, initiationResult.getRequestId());

            String redirectUrl = createRedirectUrl(initiationResult, context.getContextIdentifier(),
                    tenantDomain, organizationId, timeoutMs);

            response.sendRedirect(redirectUrl);

        } catch (VPAuthenticatorException | IOException e) {
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getMessage(), e);
        }
    }

    /**
     * Process the authentication response from the wallet.
     *
     * @param request  HTTP request.
     * @param response HTTP response.
     * @param context  Authentication context.
     * @throws AuthenticationFailedException If authentication fails.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String subjectClaimName = VPAuthenticatorUtil.resolveSubjectClaimName(context.getExternalIdP());
        if (StringUtils.isBlank(subjectClaimName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No subject attribute configured on Digital Wallet IdP; will fall back to cnf claim.");
            }
        }

        String requestId = (String) context.getProperty(CONTEXT_VP_REQUEST_ID);
        if (StringUtils.isBlank(requestId)) {
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    "VP request ID not found in authentication context.");
        }

        VPFlowSession session;
        try {
            session = VPDataHolder.getVPFlowService().getSession(requestId);
        } catch (VPAuthenticatorServerException e) {
            LOG.error("Failed to retrieve VP session for requestId: " + requestId, e);
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    "An internal error occurred while retrieving the VP session.", e);
        }
        if (session == null) {
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getMessage());
        }

        PresentationVerificationResult verificationResult = session.getVerificationResult();
        if (verificationResult == null) {
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.NO_VERIFIED_CLAIMS.getCode(),
                    VPAuthenticatorErrorCode.NO_VERIFIED_CLAIMS.getMessage());
        }

        VPDataHolder.getVPFlowService().removeSession(requestId);

        Map<String, Object> verifiedClaims = verificationResult.getVerifiedClaims() != null
                ? verificationResult.getVerifiedClaims()
                : Collections.emptyMap();

        List<PresentationMetadata> metadataList = verificationResult.getCredentialMetadataList();
        PresentationMetadata metadata = (metadataList != null && !metadataList.isEmpty()) ? metadataList.get(0) : null;

        String subjectIdentifier = VPAuthenticatorUtil.resolveSubjectIdentifier(
                verifiedClaims, subjectClaimName, metadata);
        if (subjectIdentifier == null) {
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.VERIFICATION_FAILED.getCode(),
                    "Could not determine subject identifier: " + (StringUtils.isNotBlank(subjectClaimName)
                            ? "configured attribute '" + subjectClaimName + "' not found in credential claims, and"
                            : "no subject attribute configured, and")
                            + " no usable cnf claim found in the verified credential.");
        }

        String idpName = context.getExternalIdP() != null
                ? context.getExternalIdP().getIdPName() : null;

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(subjectIdentifier, idpName);
        authenticatedUser.setTenantDomain(session.getTenantDomain());

        Map<ClaimMapping, String> federatedAttributes = buildUserAttributes(verifiedClaims, context.getExternalIdP());
        if (!federatedAttributes.isEmpty()) {
            authenticatedUser.setUserAttributes(federatedAttributes);
        }

        context.setSubject(authenticatedUser);
    }

    /**
     * Builds the federated user attribute map from the verified credential claims using
     * the IdP claim mappings. Only claims with a matching remote-to-local mapping are included.
     *
     * @param verifiedClaims the subject-attribute claims extracted from the verified credential
     * @param idpConfig      the IdP configuration carrying the claim mappings, or {@code null}
     * @return a map of {@link ClaimMapping} to claim value strings, ready for the authenticated user
     */
    private Map<ClaimMapping, String> buildUserAttributes(Map<String, Object> verifiedClaims,
                                                          ExternalIdPConfig idpConfig) {

        Map<ClaimMapping, String> federatedAttributes = new HashMap<>();
        ClaimMapping[] claimMappings = (idpConfig != null
                && idpConfig.getIdentityProvider() != null
                && idpConfig.getIdentityProvider().getClaimConfig() != null)
                ? idpConfig.getIdentityProvider().getClaimConfig().getClaimMappings() : null;

        if (claimMappings == null || claimMappings.length == 0) {
            return federatedAttributes;
        }

        for (ClaimMapping claimMapping : claimMappings) {
            if (claimMapping.getRemoteClaim() == null || claimMapping.getLocalClaim() == null
                    || StringUtils.isBlank(claimMapping.getRemoteClaim().getClaimUri())
                    || StringUtils.isBlank(claimMapping.getLocalClaim().getClaimUri())) {
                continue;
            }
            Object value = verifiedClaims.get(claimMapping.getRemoteClaim().getClaimUri());
            if (value != null && StringUtils.isNotBlank(value.toString())) {
                federatedAttributes.put(ClaimMapping.build(
                        claimMapping.getLocalClaim().getClaimUri(),
                        claimMapping.getRemoteClaim().getClaimUri(), null, false), value.toString());
            }
        }
        return federatedAttributes;
    }

    /**
     * Builds the redirect URL for the wallet login page, appending all required query parameters.
     *
     * @param initiationResult the result from the VP flow service containing the request ID and wallet URL
     * @param sessionDataKey   the IS authentication context identifier (distinct from the VP requestId)
     * @param tenantDomain     the resolved tenant domain for the current authentication
     * @param organizationId   the organization ID, or empty string if not in an org context
     * @return the fully constructed redirect URL
     */
    private String createRedirectUrl(VPFlowInitiationResult initiationResult, String sessionDataKey,
                                     String tenantDomain, String organizationId, long timeoutMs) {

        String rootTenantDomain = StringUtils.defaultIfBlank(
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain(), tenantDomain);

        return new StringBuilder(WALLET_LOGIN_PAGE)
                .append('?').append(PARAM_SESSION_DATA_KEY).append('=')
                        .append(encode(sessionDataKey))
                .append('&').append(PARAM_REQUEST_ID).append('=')
                        .append(encode(initiationResult.getRequestId()))
                .append('&').append(PARAM_WALLET_URL).append('=')
                        .append(encode(StringUtils.defaultString(initiationResult.getWalletUrl())))
                .append('&').append(PARAM_TENANT_DOMAIN).append('=')
                        .append(encode(StringUtils.defaultString(tenantDomain)))
                .append('&').append(PARAM_ORG_ID).append('=')
                        .append(encode(StringUtils.defaultString(organizationId)))
                .append('&').append(PARAM_ROOT_TENANT_DOMAIN).append('=').append(encode(rootTenantDomain))
                .append('&').append(PARAM_SESSION_TTL_MS).append('=').append(timeoutMs)
                .toString();
    }

    /**
     * URL-encodes a string value using UTF-8.
     *
     * @param value the string to encode
     * @return the URL-encoded string
     */
    private static String encode(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        String status = getValidatedParameter(request, PARAM_STATUS);

        if (StringUtils.isNotBlank(status)) {
            return handleStatusCallback(request, response, context, status);
        }

        return super.process(request, response, context);
    }

    /**
     * Handles the wallet callback by routing on the {@code status} parameter.
     * {@code success} triggers full response processing; {@code failed} clears the session
     * and retries the authentication step.
     *
     * @param request  the HTTP request carrying the status callback
     * @param response the HTTP response
     * @param context  the current authentication context
     * @param status   the callback status value ({@code success} or {@code failed})
     * @return {@link AuthenticatorFlowStatus#SUCCESS_COMPLETED} on success,
     *         or {@link AuthenticatorFlowStatus#INCOMPLETE} for unrecognised status values
     * @throws AuthenticationFailedException if status is {@code failed} or response processing fails
     */
    private AuthenticatorFlowStatus handleStatusCallback(HttpServletRequest request,
                                                         HttpServletResponse response,
                                                         AuthenticationContext context,
                                                         String status)
            throws AuthenticationFailedException {

        if (STATUS_SUCCESS.equals(status)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (STATUS_FAILED.equals(status)) {
            VPDataHolder.getVPFlowService().removeSession((String) context.getProperty(CONTEXT_VP_REQUEST_ID));
            context.setRetrying(true);
            throw new AuthenticationFailedException(
                    VPAuthenticatorErrorCode.VERIFICATION_FAILED.getCode(),
                    VPAuthenticatorErrorCode.VERIFICATION_FAILED.getMessage());
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return StringUtils.trimToNull(getValidatedParameter(request, PARAM_SESSION_DATA_KEY));
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String sessionDataKey = StringUtils.trimToNull(
                getValidatedParameter(request, PARAM_SESSION_DATA_KEY));
        String vpRequestId = StringUtils.trimToNull(
                getValidatedParameter(request, PARAM_VP_REQUEST_ID));
        String status = StringUtils.trimToNull(
                getValidatedParameter(request, PARAM_STATUS));

        return StringUtils.isNotBlank(status) && StringUtils.isNotBlank(sessionDataKey)
                && StringUtils.isNotBlank(vpRequestId);
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property presentationDefId = new Property();
        presentationDefId.setName(PROP_PRESENTATION_DEFINITION_ID);
        presentationDefId.setDisplayName(PROP_PRESENTATION_DEFINITION_ID_DISPLAY);
        presentationDefId.setDescription(PROP_PRESENTATION_DEFINITION_ID_DESC);
        presentationDefId.setDisplayOrder(DISPLAY_ORDER_PRESENTATION_DEFINITION);
        presentationDefId.setRequired(false);
        configProperties.add(presentationDefId);

        Property timeout = new Property();
        timeout.setName(PROP_TIMEOUT_SECONDS);
        timeout.setDisplayName(PROP_TIMEOUT_SECONDS_DISPLAY);
        timeout.setDescription(PROP_TIMEOUT_SECONDS_DESC);
        timeout.setDisplayOrder(DISPLAY_ORDER_TIMEOUT);
        timeout.setDefaultValue(PROP_TIMEOUT_DEFAULT_VALUE);
        timeout.setRequired(false);
        configProperties.add(timeout);

        return configProperties;
    }

    private String getValidatedParameter(HttpServletRequest request, String name) {

        return StringUtils.trimToNull(request.getParameter(name));
    }
}
