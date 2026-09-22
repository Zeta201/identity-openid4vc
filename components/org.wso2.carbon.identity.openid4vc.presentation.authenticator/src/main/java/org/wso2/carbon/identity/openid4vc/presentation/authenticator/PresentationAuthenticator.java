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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.PresentationAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.PresentationAuthenticatorDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.PresentationAuthenticatorDiagnosticLogger;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.PresentationAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.SESSION_TTL_MS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.WALLET_URL;

/**
 * OpenID for Verifiable Presentations (OpenID4VP) authenticator for WSO2 Identity Server.
 *
 * <p>This authenticator implements the OpenID for Verifiable Presentations (OpenID4VP) protocol
 * to authenticate users by verifying their verifiable credentials from a digital wallet.</p>
 */
public class PresentationAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(PresentationAuthenticator.class);
    private static final PresentationAuthenticatorDiagnosticLogger DIAGNOSTIC_LOG =
            new PresentationAuthenticatorDiagnosticLogger();

    private static final String AUTHENTICATOR_NAME = "PresentationAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";
    private static final String STATUS_SUCCESS = "success";
    private static final String STATUS_FAILED = "failed";
    private static final String WALLET_LOGIN_PAGE = "/authenticationendpoint/wallet_login.jsp";
    private static final String PARAM_SESSION_DATA_KEY = "sessionDataKey";
    private static final String PARAM_REQUEST_ID = "requestId";
    private static final String PARAM_TENANT_DOMAIN = "tenantDomain";
    private static final String PARAM_ORG_ID = "orgId";
    private static final String PARAM_ROOT_TENANT_DOMAIN = "rootTenantDomain";
    private static final String PARAM_STATUS = "status";
    private static final String PARAM_ERROR_TYPE = "error_type";

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

        try {

            String tenantDomain = CommonUtil.resolveTenantDomain();

            String presentationDefinitionId = MapUtils.getString(
                    context.getAuthenticatorProperties(), PROP_PRESENTATION_DEFINITION_ID);
            if (StringUtils.isBlank(presentationDefinitionId)) {
                throw new AuthenticationFailedException(
                        PresentationAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION.getCode(),
                        PresentationAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION.getMessage());
            }

            PresentationRequestResponseDTO presentationRequestResponse = PresentationAuthenticatorDataHolder.
                    getInstance().getPresentationSessionService().
                    startPresentationSession(presentationDefinitionId, tenantDomain);

            context.setProperty(VP_REQUEST_ID, presentationRequestResponse.getRequestId());
            DIAGNOSTIC_LOG.logVPFlowInitiated(presentationRequestResponse.getRequestId(), tenantDomain);

            // Sub-organizations are not supported; the wallet login page's org-based
            // redirect handling is left in place for org-unaware tenant resolution only.
            String redirectUrl = createRedirectUrl(presentationRequestResponse, context.getContextIdentifier(),
                    tenantDomain, StringUtils.EMPTY);

            response.sendRedirect(redirectUrl);

        } catch (PresentationCoreException e) {
            DIAGNOSTIC_LOG.logVPFlowInitiationFailed(PresentationAuthenticatorErrorCode.VP_FLOW_INITIATION_ERROR);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.VP_FLOW_INITIATION_ERROR.getCode(),
                    PresentationAuthenticatorErrorCode.VP_FLOW_INITIATION_ERROR.getMessage(), e);
        } catch (IOException e) {
            DIAGNOSTIC_LOG.logVPFlowInitiationFailed(PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                    PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getMessage(), e);
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

        String subjectClaimName = PresentationAuthenticatorUtil.resolveSubjectClaimName(context.getExternalIdP());
        if (StringUtils.isBlank(subjectClaimName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No subject attribute configured on Digital Wallet IdP; will fall back to cnf claim.");
            }
        }

        String requestId = (String) context.getProperty(VP_REQUEST_ID);
        if (StringUtils.isBlank(requestId)) {
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    PresentationAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getMessage());
        }

        VPSession session;
        try {
            String tenantDomain = CommonUtil.resolveTenantDomain();
            session = PresentationAuthenticatorDataHolder.getInstance().getPresentationSessionService().
                    getPresentationSession(requestId, tenantDomain);
        } catch (PresentationCoreClientException e) {
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId, PresentationAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    PresentationAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getMessage(), e);
        } catch (PresentationCoreException e) {
            LOG.error("Failed to retrieve VP session for requestId: " + requestId, e);
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId,
                    PresentationAuthenticatorErrorCode.VP_SESSION_RETRIEVAL_ERROR);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.VP_SESSION_RETRIEVAL_ERROR.getCode(),
                    PresentationAuthenticatorErrorCode.VP_SESSION_RETRIEVAL_ERROR.getMessage(), e);
        }

        VerificationResponseDTO verificationResponse = session.getVerificationResponse();
        if (verificationResponse == null) {
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId, PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS.getCode(),
                    PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS.getMessage());
        }

        Map<String, Object> subjectClaims = verificationResponse.getSubjectClaims();

        String subjectIdentifier = PresentationAuthenticatorUtil.resolveSubjectIdentifier(
                subjectClaims, subjectClaimName, verificationResponse);
        if (subjectIdentifier == null) {
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId, PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS.getCode(),
                    PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS.getMessage());
        }

        String idpName = context.getExternalIdP() != null
                ? context.getExternalIdP().getIdPName() : null;

        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(subjectIdentifier, idpName);
        authenticatedUser.setTenantDomain(session.getTenantDomain());

        Map<ClaimMapping, String> federatedAttributes = PresentationAuthenticatorUtil.
                buildUserAttributes(subjectClaims, context.getExternalIdP());
        if (!federatedAttributes.isEmpty()) {
            authenticatedUser.setUserAttributes(federatedAttributes);
        }

        context.setSubject(authenticatedUser);
    }

    /**
     * Builds the redirect URL for the wallet login page, appending all required query parameters.
     *
     * @param presentationRequestResponse the result from the VP flow service containing the request ID and wallet URL
     * @param sessionDataKey   the IS authentication context identifier (distinct from the VP requestId)
     * @param tenantDomain     the resolved tenant domain for the current authentication
     * @param organizationId   the organization ID, or empty string if not in an org context
     * @return the fully constructed redirect URL
     */
    private String createRedirectUrl(PresentationRequestResponseDTO presentationRequestResponse, String sessionDataKey,
                                     String tenantDomain, String organizationId) {

        String rootTenantDomain = StringUtils.defaultIfBlank(
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain(), tenantDomain);
        long sessionTtlMs = Math.max(0, presentationRequestResponse.getExpiresAt() - System.currentTimeMillis());

        return WALLET_LOGIN_PAGE +
                '?' + PARAM_SESSION_DATA_KEY + '=' +
                URLEncoder.encode(sessionDataKey, StandardCharsets.UTF_8) +
                '&' + PARAM_REQUEST_ID + '=' +
                URLEncoder.encode(presentationRequestResponse.getRequestId(), StandardCharsets.UTF_8) +
                '&' + WALLET_URL + '=' +
                URLEncoder.encode(StringUtils.defaultString(presentationRequestResponse.getWalletUrl()),
                        StandardCharsets.UTF_8) +
                '&' + PARAM_TENANT_DOMAIN + '=' +
                URLEncoder.encode(StringUtils.defaultString(tenantDomain), StandardCharsets.UTF_8) +
                '&' + PARAM_ORG_ID + '=' +
                URLEncoder.encode(StringUtils.defaultString(organizationId), StandardCharsets.UTF_8) +
                '&' + PARAM_ROOT_TENANT_DOMAIN + '=' + URLEncoder.encode(rootTenantDomain, StandardCharsets.UTF_8) +
                '&' + SESSION_TTL_MS + '=' + sessionTtlMs;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        String status = StringUtils.trimToNull(request.getParameter(PARAM_STATUS));

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
            DIAGNOSTIC_LOG.logVPAuthenticationSuccess((String) context.getProperty(VP_REQUEST_ID));
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (STATUS_FAILED.equals(status)) {
            String requestId = (String) context.getProperty(VP_REQUEST_ID);
            String errorType = StringUtils.trimToNull(request.getParameter(PARAM_ERROR_TYPE));
            String tenantDomain = null;
            try {
                tenantDomain = CommonUtil.resolveTenantDomain();
                if (errorType == null) {
                    VPSession failedSession = PresentationAuthenticatorDataHolder.getInstance().
                            getPresentationSessionService().getPresentationSession(requestId, tenantDomain);
                    errorType = failedSession != null ? failedSession.getErrorType() : null;
                }
            } catch (PresentationCoreException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not retrieve error type from VP session for requestId: " + requestId, e);
                }
            }
            DIAGNOSTIC_LOG.logVPAuthenticationFailed(requestId, errorType);
            try {
                PresentationAuthenticatorDataHolder.getInstance().getPresentationSessionService().
                        handleSessionFailed(requestId, errorType, null, tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error("Failed to mark session as failed for requestId: " + requestId, ex);
            }
            context.setRetrying(true);
            throw new AuthenticationFailedException(
                    PresentationAuthenticatorErrorCode.VERIFICATION_FAILED.getCode(),
                    PresentationAuthenticatorErrorCode.VERIFICATION_FAILED.getMessage());
        }

        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return StringUtils.trimToNull(request.getParameter(PARAM_SESSION_DATA_KEY));
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String sessionDataKey = StringUtils.trimToNull(request.getParameter(PARAM_SESSION_DATA_KEY));
        String vpRequestId = StringUtils.trimToNull(request.getParameter(VP_REQUEST_ID));
        String status = StringUtils.trimToNull(request.getParameter(PARAM_STATUS));

        return StringUtils.isNotBlank(status) && StringUtils.isNotBlank(sessionDataKey)
                && StringUtils.isNotBlank(vpRequestId);
    }

}
