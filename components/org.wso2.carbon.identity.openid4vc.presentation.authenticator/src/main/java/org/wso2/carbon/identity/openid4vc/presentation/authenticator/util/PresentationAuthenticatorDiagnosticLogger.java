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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.PresentationAuthenticatorLogConstants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.PresentationAuthenticatorErrorCode;
import org.wso2.carbon.utils.DiagnosticLog;

/**
 * Diagnostic logger for the OpenID4VP authenticator flow.
 */
public class PresentationAuthenticatorDiagnosticLogger {

    public void logVPFlowInitiationFailed(PresentationAuthenticatorErrorCode errorCode) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        triggerLogEvent(
                initializeDiagnosticLogBuilder(
                        PresentationAuthenticatorLogConstants.ActionIDs.INITIATE_VP_FLOW,
                        "VP authentication flow initiation failed.",
                        DiagnosticLog.ResultStatus.FAILED)
                        .inputParam("errorType", errorCode.getErrorType())
                        .inputParam("errorDescription", errorCode.getDescription()));
    }

    public void logVPAuthenticationError(String requestId, PresentationAuthenticatorErrorCode errorCode) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder builder = initializeDiagnosticLogBuilder(
                PresentationAuthenticatorLogConstants.ActionIDs.COMPLETE_VP_AUTHENTICATION,
                "VP authentication failed.",
                DiagnosticLog.ResultStatus.FAILED)
                .inputParam("errorType", errorCode.getErrorType())
                .inputParam("errorDescription", errorCode.getDescription());
        if (requestId != null) {
            builder.configParam("requestId", requestId);
        }
        triggerLogEvent(builder);
    }

    public void logVPFlowInitiated(String requestId, String tenantDomain) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        triggerLogEvent(
                initializeDiagnosticLogBuilder(
                        PresentationAuthenticatorLogConstants.ActionIDs.INITIATE_VP_FLOW,
                        "VP authentication flow initiated.",
                        DiagnosticLog.ResultStatus.SUCCESS)
                        .configParam("requestId", requestId)
                        .configParam("tenantDomain", tenantDomain));
    }

    public void logVPAuthenticationSuccess(String requestId) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        triggerLogEvent(
                initializeDiagnosticLogBuilder(
                        PresentationAuthenticatorLogConstants.ActionIDs.COMPLETE_VP_AUTHENTICATION,
                        "VP authentication completed successfully.",
                        DiagnosticLog.ResultStatus.SUCCESS)
                        .configParam("requestId", requestId));
    }

    public void logVPAuthenticationFailed(String requestId, String errorType) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        triggerLogEvent(
                initializeDiagnosticLogBuilder(
                        PresentationAuthenticatorLogConstants.ActionIDs.COMPLETE_VP_AUTHENTICATION,
                        "VP authentication failed.",
                        DiagnosticLog.ResultStatus.FAILED)
                        .configParam("requestId", requestId)
                        .inputParam("errorType", errorType != null ? errorType : "unknown"));
    }

    private DiagnosticLog.DiagnosticLogBuilder initializeDiagnosticLogBuilder(String actionId, String message,
            DiagnosticLog.ResultStatus resultStatus) {

        DiagnosticLog.DiagnosticLogBuilder diagLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                PresentationAuthenticatorLogConstants.VP_AUTHENTICATOR_COMPONENT_ID, actionId);
        diagLogBuilder
                .resultMessage(message)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(resultStatus);
        return diagLogBuilder;
    }

    private void triggerLogEvent(DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder) {

        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }
}
