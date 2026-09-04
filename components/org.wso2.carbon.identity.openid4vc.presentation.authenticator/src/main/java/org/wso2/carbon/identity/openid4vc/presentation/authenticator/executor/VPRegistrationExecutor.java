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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowInitiationResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * Flow executor for wallet-based self-registration via OpenID4VP.
 * Initiation returns {@code STATUS_EXTERNAL_REDIRECTION} with the wallet deep-link;
 * completion polls the VP session and returns {@code STATUS_COMPLETE}, re-issues the
 * redirection when still {@code ACTIVE}, or returns {@code STATUS_USER_ERROR} on failure.
 */
public class VPRegistrationExecutor extends AuthenticationExecutor {

    private static final Log LOG = LogFactory.getLog(VPRegistrationExecutor.class);

    private static final String EXECUTOR_NAME = Constants.EXECUTOR_NAME;
    private static final String AMR_VALUE = Constants.AUTHENTICATOR_NAME;

    // Package-private so unit tests in the same package can reference these keys directly.
    static final String VP_REQUEST_ID = Constants.CONTEXT_VP_REQUEST_ID;
    static final String WALLET_URL = Constants.CONTEXT_WALLET_URL;
    static final String SESSION_TTL_MS = Constants.CONTEXT_SESSION_TTL_MS;

    private final VPFlowService vpFlowService;

    /**
     * Creates the executor with the given VP flow service.
     *
     * @param vpFlowService the service used to initiate and retrieve VP flow sessions
     */
    public VPRegistrationExecutor(VPFlowService vpFlowService) {

        this.vpFlowService = vpFlowService;
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
    public ExecutorResponse execute(FlowExecutionContext context) {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(VPConstants.ConfigKeys.FEATURE_ENABLED))) {
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorMessage("OpenID4VP feature is disabled.");
            return response;
        }

        try {
            if (context.getProperty(VP_REQUEST_ID) == null) {
                return initiateVPFlow(context);
            }
            return processVPResponse(context);
        } catch (VPAuthenticatorException e) {
            LOG.error("VP registration executor failed for requestId: " + context.getProperty(VP_REQUEST_ID), e);

            vpFlowService.failSession((String) context.getProperty(VP_REQUEST_ID),
                    "VP registration failed: " + e.getMessage());
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorMessage("VP registration failed: " + e.getMessage());
            return response;
        }
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        String requestId = (String) context.getProperty(VP_REQUEST_ID);
        if (requestId != null) {
            vpFlowService.removeSession(requestId);
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
     * @throws VPAuthenticatorException if the VP flow service fails to initiate the session
     */
    private ExecutorResponse initiateVPFlow(FlowExecutionContext context) throws VPAuthenticatorException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String presentationDefinitionId = authenticatorProperties.get(Constants.PROP_PRESENTATION_DEFINITION_ID);
        long timeoutMs = VPAuthenticatorUtil.resolveTimeoutMs(authenticatorProperties);

        VPFlowInitiationResult flowResult = vpFlowService.initiate(
                presentationDefinitionId, VPAuthenticatorUtil.resolveTenantDomain(), timeoutMs);

        Map<String, Object> contextProperties = new HashMap<>();
        contextProperties.put(VP_REQUEST_ID, flowResult.getRequestId());

        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, flowResult.getWalletUrl());
        additionalInfo.put(VP_REQUEST_ID, flowResult.getRequestId());
        additionalInfo.put(SESSION_TTL_MS, String.valueOf(timeoutMs));

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
    private ExecutorResponse processVPResponse(FlowExecutionContext context) throws VPAuthenticatorException {

        String requestId = (String) context.getProperty(VP_REQUEST_ID);
        VPFlowSession session = vpFlowService.getSession(requestId);

        if (session == null) {
            return userError("VP session expired or not found.");
        }

        VPFlowStatus status = session.getStatus();
        switch (status) {
            case VERIFIED:
                return buildCompleteResponse(context, session);

            case FAILED:
                VerificationResult verificationResult = session.getVerificationResult();
                String failureReason = (verificationResult != null
                        && !verificationResult.getErrors().isEmpty())
                        ? verificationResult.getErrors().get(0)
                        : "Wallet verification failed.";
                return userError(failureReason);

            case ACTIVE:
                String walletUrl = session.getWalletUrl();
                long remainingMs = Math.max(0, session.getExpiresAt() - System.currentTimeMillis());
                Map<String, String> additionalInfo = new HashMap<>();
                additionalInfo.put(REDIRECT_URL, StringUtils.defaultString(walletUrl));
                additionalInfo.put(VP_REQUEST_ID, requestId);
                if (StringUtils.isNotBlank(walletUrl)) {
                    additionalInfo.put(WALLET_URL, walletUrl);
                }
                additionalInfo.put(SESSION_TTL_MS, String.valueOf(remainingMs));
                ExecutorResponse redirectResponse = new ExecutorResponse();
                redirectResponse.setResult(STATUS_EXTERNAL_REDIRECTION);
                redirectResponse.setRequiredData(Collections.singletonList(VP_REQUEST_ID));
                redirectResponse.setAdditionalInfo(additionalInfo);
                return redirectResponse;

            case EXPIRED:
                return userError("VP session has expired.");

            default:
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
     * @return {@code STATUS_COMPLETE} response with mapped user claims,
     *         or {@code STATUS_USER_ERROR} if the subject identifier cannot be resolved
     */
    private ExecutorResponse buildCompleteResponse(FlowExecutionContext context,
                                                   VPFlowSession session) {

        VerificationResult result = session.getVerificationResult();
        List<PresentationMetadata> metadataList = result != null ? result.getCredentialMetadataList() : null;
        PresentationMetadata metadata = (metadataList != null && !metadataList.isEmpty()) ? metadataList.get(0) : null;

        Map<String, Object> credentialClaims = (result != null && result.getVerifiedClaims() != null)
                ? result.getVerifiedClaims()
                : Collections.emptyMap();

        String subjectIdentifier = resolveSubjectIdentifier(credentialClaims, metadata, context.getExternalIdPConfig());
        if (StringUtils.isBlank(subjectIdentifier)) {
            String subjectClaimName = VPAuthenticatorUtil.resolveSubjectClaimName(context.getExternalIdPConfig());
            return userError("Cannot resolve subject identifier: the configured claim '"
                    + (subjectClaimName != null ? subjectClaimName : "(none)")
                    + "' was not found in the verified credential.");
        }

        Map<String, Object> localClaims = buildLocalClaims(credentialClaims, subjectIdentifier,
                context.getExternalIdPConfig());
        registerFederatedAssociation(context, subjectIdentifier);

        vpFlowService.removeSession((String) context.getProperty(VP_REQUEST_ID));

        ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
        response.setUpdatedUserClaims(localClaims);
        return response;
    }

    private String resolveSubjectIdentifier(Map<String, Object> credentialClaims,
                                            PresentationMetadata metadata,
                                            ExternalIdPConfig idpConfig) {

        String subjectClaimName = VPAuthenticatorUtil.resolveSubjectClaimName(idpConfig);
        return VPAuthenticatorUtil.resolveSubjectIdentifier(credentialClaims, subjectClaimName, metadata);
    }

    private Map<String, Object> buildLocalClaims(Map<String, Object> credentialClaims,
                                                  String subjectIdentifier,
                                                  ExternalIdPConfig idpConfig) {

        Map<String, Object> localClaims = mapToLocalClaims(credentialClaims, idpConfig);
        String subjectClaimName = VPAuthenticatorUtil.resolveSubjectClaimName(idpConfig);
        String usernameValue = VPAuthenticatorUtil.resolveSubjectIdentifier(credentialClaims, subjectClaimName, null);
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
        response.setErrorMessage(message);
        return response;
    }

}
