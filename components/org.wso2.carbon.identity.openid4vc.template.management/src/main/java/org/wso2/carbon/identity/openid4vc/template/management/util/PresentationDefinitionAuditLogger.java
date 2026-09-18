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

package org.wso2.carbon.identity.openid4vc.template.management.util;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.utils.AuditLog;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Audit logger for presentation definition management operations.
 * Logs create, update, delete, and issuer configuration replacement actions
 * using the WSO2 central audit log framework.
 */
public class PresentationDefinitionAuditLogger {

    private static final PresentationDefinitionAuditLogger INSTANCE = new PresentationDefinitionAuditLogger();

    private static final String TARGET_TYPE = "PresentationDefinition";

    private static final String FIELD_ID = "Id";
    private static final String FIELD_IDENTIFIER = "Identifier";
    private static final String FIELD_DISPLAY_NAME = "DisplayName";
    private static final String FIELD_DESCRIPTION = "Description";
    private static final String FIELD_CREDENTIAL_COUNT = "CredentialCount";
    private static final String FIELD_CREDENTIAL_IDENTIFIER = "CredentialIdentifier";
    private static final String FIELD_ISSUER_COUNT = "IssuerCount";

    private PresentationDefinitionAuditLogger() {

    }

    public static PresentationDefinitionAuditLogger getInstance() {

        return INSTANCE;
    }

    /**
     * Enum for presentation definition audit log actions.
     */
    private enum Action {

        ADD_PRESENTATION_DEFINITION("add-presentation-definition"),
        UPDATE_PRESENTATION_DEFINITION("update-presentation-definition"),
        DELETE_PRESENTATION_DEFINITION("delete-presentation-definition"),
        REPLACE_ISSUER_CONFIGS("replace-issuer-configs");

        private final String logAction;

        Action(String logAction) {

            this.logAction = logAction;
        }

        private String value() {

            return logAction;
        }
    }

    /**
     * Logs the creation of a presentation definition.
     *
     * @param definition the created presentation definition
     */
    public void logCreatePresentationDefinition(PresentationDefinition definition) {

        triggerAuditLogEvent(definition.getId(), Action.ADD_PRESENTATION_DEFINITION,
                buildDefinitionDataMap(definition));
    }

    /**
     * Logs the update of a presentation definition.
     *
     * @param definition the updated presentation definition
     */
    public void logUpdatePresentationDefinition(PresentationDefinition definition) {

        triggerAuditLogEvent(definition.getId(), Action.UPDATE_PRESENTATION_DEFINITION,
                buildDefinitionDataMap(definition));
    }

    /**
     * Logs the deletion of a presentation definition.
     *
     * @param definitionId the ID of the deleted presentation definition
     */
    public void logDeletePresentationDefinition(String definitionId) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_ID, definitionId);
        triggerAuditLogEvent(definitionId, Action.DELETE_PRESENTATION_DEFINITION, data);
    }

    /**
     * Logs the replacement of issuer configurations for a credential within a presentation definition.
     *
     * @param definitionId         the ID of the parent presentation definition
     * @param credentialIdentifier the identifier of the target credential
     * @param issuers              the replacement issuer list
     */
    public void logReplaceIssuerConfigs(String definitionId, String credentialIdentifier,
            List<Issuer> issuers) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_ID, definitionId);
        data.put(FIELD_CREDENTIAL_IDENTIFIER, credentialIdentifier);
        data.put(FIELD_ISSUER_COUNT, issuers != null ? issuers.size() : 0);
        triggerAuditLogEvent(definitionId, Action.REPLACE_ISSUER_CONFIGS, data);
    }

    private Map<String, Object> buildDefinitionDataMap(PresentationDefinition definition) {

        Map<String, Object> data = new HashMap<>();
        data.put(FIELD_ID, definition.getId());
        data.put(FIELD_IDENTIFIER, definition.getIdentifier());
        data.put(FIELD_DISPLAY_NAME, definition.getDisplayName());
        data.put(FIELD_DESCRIPTION, definition.getDescription());
        data.put(FIELD_CREDENTIAL_COUNT,
                definition.getCredentials() != null ? definition.getCredentials().size() : 0);
        return data;
    }

    private void triggerAuditLogEvent(String targetId, Action action, Map<String, Object> dataMap) {

        String initiatorId = getInitiatorId();
        AuditLog.AuditLogBuilder auditLogBuilder = new AuditLog.AuditLogBuilder(
                initiatorId,
                LoggerUtils.getInitiatorType(initiatorId),
                targetId,
                TARGET_TYPE,
                action.value())
                .data(dataMap);
        LoggerUtils.triggerAuditLogEvent(auditLogBuilder);
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
