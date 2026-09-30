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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.executor;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.flow.mgt.model.MessageDTO;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.PresentationAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.PresentationAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.PresentationAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.PresentationAuthenticatorDiagnosticLogger;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.PresentationAuthenticatorExceptionHandler;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.PresentationAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession.VPSessionStatus;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationCoreService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.PROP_PRESENTATION_DEFINITION_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.SESSION_TTL_MS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.VP_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorConstants.WALLET_URL;

/**
 * Flow executor for wallet-based self-registration via OpenID4VP.
 * Initiation returns {@code STATUS_EXTERNAL_REDIRECTION} with the wallet deep-link;
 * completion polls the VP session and returns {@code STATUS_COMPLETE}, re-issues the
 * redirection when still {@code ACTIVE}, or returns {@code STATUS_USER_ERROR} on failure.
 */
public class PresentationExecutor extends AuthenticationExecutor {

    private static final Log LOG = LogFactory.getLog(PresentationExecutor.class);
    private static final PresentationAuthenticatorDiagnosticLogger DIAGNOSTIC_LOG =
            new PresentationAuthenticatorDiagnosticLogger();

    private static final String EXECUTOR_NAME = "PresentationExecutor";
    private static final String AMR_VALUE = "PresentationAuthenticator";

    private PresentationCoreService vpSessionService;

    /**
     * Creates the executor with the given VP flow service.
     *
     * @param vpSessionService the service used to initiate and retrieve VP flow sessions
     */
    public PresentationExecutor(PresentationCoreService vpSessionService) {

        this.vpSessionService = vpSessionService;
    }

    @Override
    public String getName() {

        return EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {

        return AMR_VALUE;
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .associatedAuthenticator(AMR_VALUE)
                .connectionRequired(true)
                .build();
    }

    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        return Collections.singleton(FlowTypes.REGISTRATION);
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        String tenantDomain = CommonUtil.resolveTenantDomain();
        try {
            if (context.getProperty(VP_REQUEST_ID) == null) {
                return initiateVPFlow(context);
            }
            return processVPResponse(context);
        } catch (PresentationAuthenticatorClientException e) {
            String requestId = (String) context.getProperty(VP_REQUEST_ID);
            LOG.warn("VP registration flow failed due to client error. requestId: " + requestId, e);
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId, e.getErrorCode());
            try {
                vpSessionService.handleSessionFailed(requestId, e.getErrorType(), e.getMessage(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error("Failed to mark session as failed for requestId: " + requestId, ex);
            }
            return userError(e.getMessage());
        } catch (PresentationAuthenticatorException e) {
            String requestId = (String) context.getProperty(VP_REQUEST_ID);
            LOG.error("VP registration flow failed due to server error. requestId: " + requestId, e);
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId,
                    PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR);
            try {
                vpSessionService.handleSessionFailed(requestId,
                        PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getErrorType(),
                        PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR.getDescription(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error("Failed to mark session as failed for requestId: " + requestId, ex);
            }
            ExecutorResponse errorResponse = new ExecutorResponse();
            errorResponse.setResult(STATUS_ERROR);
            errorResponse.addMessage(MessageDTO.MessageType.ERROR, e.getMessage(), null);
            return errorResponse;
        }
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        String requestId = (String) context.getProperty(VP_REQUEST_ID);
        if (requestId != null) {
            try {
                vpSessionService.handleSessionFailed(requestId,
                        PresentationAuthenticatorErrorCode.FLOW_ABORTED.getErrorType(),
                        PresentationAuthenticatorErrorCode.FLOW_ABORTED.getDescription(),
                        CommonUtil.resolveTenantDomain());
            } catch (PresentationCoreException e) {
                LOG.warn("Could not mark session as failed on rollback. requestId: " + requestId);
            }
        }
        return new ExecutorResponse(STATUS_COMPLETE);
    }

    /**
     * Initiates a new VP flow: generates a request ID, calls the VP flow service, and returns
     * a redirection response pointing the user's browser to the wallet URL.
     *
     * @param context the current flow execution context
     * @return an {@link ExecutorResponse} with {@code STATUS_EXTERNAL_REDIRECTION} carrying
     *         the wallet URL and request ID in {@code additionalInfo}
     * @throws PresentationAuthenticatorException if inputs are invalid or the VP flow service fails to initiate
     *         the session
     */
    private ExecutorResponse initiateVPFlow(FlowExecutionContext context) throws PresentationAuthenticatorException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String presentationDefinitionId = authenticatorProperties.get(PROP_PRESENTATION_DEFINITION_ID);

        String tenantDomain = CommonUtil.resolveTenantDomain();
        PresentationRequestResponseDTO flowResult;
        try {
            flowResult = vpSessionService.startPresentationSession(presentationDefinitionId, tenantDomain);
        } catch (PresentationCoreClientException e) {
            throw PresentationAuthenticatorExceptionHandler.handleClientException(
                    PresentationAuthenticatorErrorCode.INVALID_PRESENTATION_DEFINITION);
        } catch (PresentationCoreException e) {
            throw PresentationAuthenticatorExceptionHandler.handleServerException(
                    PresentationAuthenticatorErrorCode.VP_FLOW_INITIATION_ERROR, e);
        }

        DIAGNOSTIC_LOG.logVPFlowInitiated(flowResult.getRequestId(), tenantDomain);

        Map<String, Object> contextProperties = new HashMap<>();
        contextProperties.put(VP_REQUEST_ID, flowResult.getRequestId());

        long sessionTtlMs = Math.max(0, flowResult.getExpiresAt() - System.currentTimeMillis());
        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, flowResult.getWalletUrl());
        additionalInfo.put(VP_REQUEST_ID, flowResult.getRequestId());
        additionalInfo.put(SESSION_TTL_MS, String.valueOf(sessionTtlMs));

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(STATUS_EXTERNAL_REDIRECTION);
        response.setContextProperty(contextProperties);
        response.setAdditionalInfo(additionalInfo);
        response.setRequiredData(Collections.singletonList(VP_REQUEST_ID));

        return response;
    }

    /**
     * Processes the VP flow response after the wallet has submitted the presentation.
     * Reads the session status and returns the appropriate executor response.
     *
     * @param context the current flow execution context carrying the {@code vp_request_id}
     * @return {@code STATUS_COMPLETE} if verified, {@code STATUS_USER_ERROR} if failed,
     *         or {@code STATUS_EXTERNAL_REDIRECTION} if still pending
     */
    private ExecutorResponse processVPResponse(FlowExecutionContext context)
            throws PresentationAuthenticatorException {

        String requestId = (String) context.getProperty(VP_REQUEST_ID);
        VPSession session;
        try {
            session = vpSessionService.getPresentationSession(requestId, CommonUtil.resolveTenantDomain());
        } catch (PresentationCoreClientException e) {
            DIAGNOSTIC_LOG.logVPAuthenticationError(requestId, PresentationAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND);
            return userError("VP session expired or not found.");
        } catch (PresentationCoreException e) {
            throw PresentationAuthenticatorExceptionHandler.handleServerException(
                    PresentationAuthenticatorErrorCode.VP_SESSION_RETRIEVAL_ERROR, e, requestId);
        }

        VPSessionStatus status = session.getStatus();
        switch (status) {
            case VERIFIED:
                return buildCompleteResponse(context, session);

            case FAILED:
                DIAGNOSTIC_LOG.logVPAuthenticationFailed(requestId, session.getErrorType());
                return userError("Wallet verification failed.");

            case ACTIVE:
                String walletUrl = session.getWalletUrl();
                long sessionTtlMs = Math.max(0, session.getExpiresAt() - System.currentTimeMillis());
                Map<String, String> additionalInfo = new HashMap<>();
                additionalInfo.put(REDIRECT_URL, StringUtils.defaultString(walletUrl));
                additionalInfo.put(VP_REQUEST_ID, requestId);
                if (StringUtils.isNotBlank(walletUrl)) {
                    additionalInfo.put(WALLET_URL, walletUrl);
                }
                additionalInfo.put(SESSION_TTL_MS, String.valueOf(sessionTtlMs));
                ExecutorResponse redirectResponse = new ExecutorResponse();
                redirectResponse.setResult(STATUS_EXTERNAL_REDIRECTION);
                redirectResponse.setRequiredData(Collections.singletonList(VP_REQUEST_ID));
                redirectResponse.setAdditionalInfo(additionalInfo);
                return redirectResponse;

            default:
                DIAGNOSTIC_LOG.logVPAuthenticationError(requestId,
                        PresentationAuthenticatorErrorCode.INTERNAL_SERVER_ERROR);
                return userError("VP session is in an unexpected state: " + status);
        }
    }

    /**
     * Builds the {@code STATUS_COMPLETE} executor response after a successful VP verification.
     * Maps credential claims to local WSO2 claim URIs, resolves the subject identifier,
     * registers the federated association, and removes the VP session from the cache.
     *
     * @param context the current flow execution context
     * @param session the verified VP flow session containing the verification result
     * @return {@code STATUS_COMPLETE} response with mapped user claims
     * @throws PresentationAuthenticatorClientException if the subject identifier cannot be resolved from the
     *         verified credential
     */
    private ExecutorResponse buildCompleteResponse(FlowExecutionContext context,
                                                   VPSession session) throws PresentationAuthenticatorException {

        VerificationResponseDTO result = session.getVerificationResponse();

        Map<String, Object> credentialClaims = result != null
                ? result.getSubjectClaims() : Collections.emptyMap();

        String subjectClaimName = PresentationAuthenticatorUtil.resolveSubjectClaimName(context.getExternalIdPConfig());
        String subjectIdentifier = PresentationAuthenticatorUtil.resolveSubjectIdentifier(
                credentialClaims, subjectClaimName, result);
        if (StringUtils.isBlank(subjectIdentifier)) {
            throw PresentationAuthenticatorExceptionHandler.handleClientException(
                    PresentationAuthenticatorErrorCode.NO_VERIFIED_CLAIMS,
                    subjectClaimName != null ? subjectClaimName : "(none)");
        }

        Map<String, Object> localClaims = buildLocalClaims(credentialClaims, subjectIdentifier, subjectClaimName,
                context.getExternalIdPConfig());
        registerFederatedAssociation(context, subjectIdentifier);

        String requestId = (String) context.getProperty(VP_REQUEST_ID);
        DIAGNOSTIC_LOG.logVPAuthenticationSuccess(requestId);
        ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
        response.setUpdatedUserClaims(localClaims);
        return response;
    }

    private Map<String, Object> buildLocalClaims(Map<String, Object> credentialClaims,
                                                  String subjectIdentifier,
                                                  String subjectClaimName,
                                                  ExternalIdPConfig idpConfig) {

        Map<String, Object> localClaims = mapToLocalClaims(credentialClaims, idpConfig);
        String usernameValue = PresentationAuthenticatorUtil.resolveSubjectIdentifier(
                credentialClaims, subjectClaimName, null);
        localClaims.put(USERNAME_CLAIM_URI, StringUtils.isNotBlank(usernameValue) ? usernameValue : subjectIdentifier);
        return localClaims;
    }

    private void registerFederatedAssociation(FlowExecutionContext context, String subjectIdentifier) {

        if (context.getExternalIdPConfig() != null) {
            context.getFlowUser().addFederatedAssociation(
                    context.getExternalIdPConfig().getIdPName(), subjectIdentifier);
        }
    }

    /**
     * Translates credential claim keys to local WSO2 claim URIs using the IdP claim mappings.
     * Claims with no matching mapping are silently dropped.
     *
     * @param credentialClaims the subject-attribute claims from the verified credential
     * @param idpConfig        the IdP configuration carrying the claim mappings, or {@code null}
     * @return a map of local claim URIs to their corresponding credential claim values
     */
    private Map<String, Object> mapToLocalClaims(Map<String, Object> credentialClaims,
                                                  ExternalIdPConfig idpConfig) {

        Map<String, Object> localClaims = new HashMap<>();
        ClaimMapping[] claimMappings = (idpConfig != null) ? idpConfig.getClaimMappings() : null;

        for (Map.Entry<String, Object> entry : credentialClaims.entrySet()) {
            String localUri = findLocalUri(entry.getKey(), claimMappings);
            if (localUri != null) {
                localClaims.put(localUri, entry.getValue());
            }
        }
        return localClaims;
    }

    /**
     * Looks up the local WSO2 claim URI for a given credential claim key.
     *
     * @param credentialClaimKey the claim name from the verified credential (e.g. {@code "email"})
     * @param claimMappings      the IdP claim mappings to search, or {@code null}
     * @return the matching local claim URI, or {@code null} if no mapping exists
     */
    private String findLocalUri(String credentialClaimKey, ClaimMapping[] claimMappings) {

        if (claimMappings != null) {
            for (ClaimMapping mapping : claimMappings) {
                if (credentialClaimKey.equals(mapping.getRemoteClaim().getClaimUri())) {
                    return mapping.getLocalClaim().getClaimUri();
                }
            }
        }
        return null;
    }

    /**
     * Builds a {@code STATUS_USER_ERROR} response with the given error message.
     *
     * @param message a human-readable description of the user-facing error
     * @return an {@link ExecutorResponse} with {@code STATUS_USER_ERROR}
     */
    private ExecutorResponse userError(String message) {

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(STATUS_USER_ERROR);
        response.addMessage(MessageDTO.MessageType.ERROR, message, null);
        return response;
    }

}
