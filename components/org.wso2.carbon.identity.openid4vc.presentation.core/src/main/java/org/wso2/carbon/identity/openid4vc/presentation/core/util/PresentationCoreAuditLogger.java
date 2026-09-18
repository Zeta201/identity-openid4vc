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

package org.wso2.carbon.identity.openid4vc.presentation.core.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.utils.AuditLog;

import java.util.HashMap;
import java.util.Map;

/**
 * Audit logger for VP session lifecycle and VP tenant configuration operations.
 * Logs session initiation, credential verification outcomes, and config updates
 * using the WSO2 central audit log framework.
 */
public class PresentationCoreAuditLogger {

    private static final Log LOG = LogFactory.getLog(PresentationCoreAuditLogger.class);
    private static final PresentationCoreAuditLogger INSTANCE = new PresentationCoreAuditLogger();

    private static final String TARGET_TYPE_VP_SESSION = "VPSession";
    private static final String TARGET_TYPE_VP_CONFIG = "VPTenantConfig";

    private static final String FIELD_REQUEST_ID = "RequestId";
    private static final String FIELD_PRESENTATION_DEFINITION_ID = "PresentationDefinitionId";
    private static final String FIELD_PRESENTATION_DEFINITION_IDENTIFIER = "PresentationDefinitionIdentifier";
    private static final String FIELD_TENANT_DOMAIN = "TenantDomain";
    private static final String FIELD_RESPONSE_MODE = "ResponseMode";
    private static final String FIELD_CREDENTIAL_ID = "CredentialId";
    private static final String FIELD_ERROR_TYPE = "ErrorType";
    private static final String FIELD_ERROR_DESCRIPTION = "ErrorDescription";
    private static final String FIELD_CLIENT_ID_SCHEME = "ClientIdScheme";

    private PresentationCoreAuditLogger() {

    }

    public static PresentationCoreAuditLogger getInstance() {

        return INSTANCE;
    }

    /**
     * Enum for VP audit log actions.
     */
    private enum Action {

        INITIATE_VP_SESSION("initiate-vp-session"),
        VP_CREDENTIAL_VERIFICATION_SUCCESS("vp-credential-verification-success"),
        VP_CREDENTIAL_VERIFICATION_FAILURE("vp-credential-verification-failure"),
        UPDATE_VP_CONFIG("update-vp-config");

        private final String logAction;

        Action(String logAction) {

            this.logAction = logAction;
        }

        private String value() {

            return logAction;
        }
    }

    /**
     * Logs the initiation of a VP session.
     *
     * @param requestId          the unique session request ID
     * @param definition         the presentation definition being requested
     * @param tenantDomain       the tenant domain for the session
     * @param responseMode       the configured response mode (e.g. {@code direct_post.jwt})
     */
    public void logVPSessionInitiated(String requestId, PresentationDefinition definition,
            String tenantDomain, String responseMode) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_REQUEST_ID, requestId);
        data.put(FIELD_PRESENTATION_DEFINITION_ID, definition.getId());
        data.put(FIELD_PRESENTATION_DEFINITION_IDENTIFIER, definition.getIdentifier());
        data.put(FIELD_TENANT_DOMAIN, tenantDomain);
        data.put(FIELD_RESPONSE_MODE, responseMode);
        triggerAuditLogEvent(requestId, TARGET_TYPE_VP_SESSION, Action.INITIATE_VP_SESSION, data);
    }

    /**
     * Logs a successful VP credential verification.
     *
     * @param requestId    the VP session request ID
     * @param credentialId the identifier of the verified credential
     * @param tenantDomain the tenant domain for the session
     */
    public void logVPCredentialVerified(String requestId, String credentialId, String tenantDomain) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_REQUEST_ID, requestId);
        data.put(FIELD_CREDENTIAL_ID, credentialId);
        data.put(FIELD_TENANT_DOMAIN, tenantDomain);
        triggerAuditLogEvent(requestId, TARGET_TYPE_VP_SESSION,
                Action.VP_CREDENTIAL_VERIFICATION_SUCCESS, data);
    }

    /**
     * Logs a failed VP credential verification.
     *
     * @param requestId        the VP session request ID
     * @param errorType        machine-readable error type
     * @param errorDescription human-readable description of the failure reason
     * @param tenantDomain     the tenant domain for the session
     */
    public void logVPCredentialVerificationFailed(String requestId, String errorType,
            String errorDescription, String tenantDomain) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_REQUEST_ID, requestId);
        data.put(FIELD_ERROR_TYPE, errorType);
        data.put(FIELD_ERROR_DESCRIPTION, errorDescription);
        data.put(FIELD_TENANT_DOMAIN, tenantDomain);
        triggerAuditLogEvent(requestId, TARGET_TYPE_VP_SESSION,
                Action.VP_CREDENTIAL_VERIFICATION_FAILURE, data);
    }

    /**
     * Logs an update to the VP tenant configuration.
     *
     * @param config       the updated configuration
     * @param tenantDomain the tenant domain whose config was updated
     */
    public void logVPConfigUpdated(VPTenantConfig config, String tenantDomain) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_TENANT_DOMAIN, tenantDomain);
        data.put(FIELD_CLIENT_ID_SCHEME, config.getClientIdScheme());
        data.put(FIELD_RESPONSE_MODE, config.getResponseMode());
        triggerAuditLogEvent(tenantDomain, TARGET_TYPE_VP_CONFIG, Action.UPDATE_VP_CONFIG, data);
    }

    private void triggerAuditLogEvent(String targetId, String targetType, Action action,
            Map<String, Object> dataMap) {

        try {
            String initiatorId = getInitiatorId();
            AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                    initiatorId,
                    LoggerUtils.getInitiatorType(initiatorId),
                    targetId,
                    targetType,
                    action.value())
                    .data(dataMap);
            LoggerUtils.triggerAuditLogEvent(auditLogBuilder);
        } catch (ExceptionInInitializerError | NoClassDefFoundError e) {
            LOG.debug("Audit event could not be triggered (Carbon runtime unavailable): " + e.getMessage());
        }
    }

    private String getInitiatorId() {

        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isBlank(username)) {
            return LoggerUtils.Initiator.System.name();
        }
        String initiator = null;
        if (StringUtils.isNotBlank(tenantDomain)) {
            initiator = IdentityUtil.getInitiatorId(username, tenantDomain);
        }
        return StringUtils.isNotBlank(initiator) ? initiator : LoggerUtils.getMaskedContent(username);
    }
}
