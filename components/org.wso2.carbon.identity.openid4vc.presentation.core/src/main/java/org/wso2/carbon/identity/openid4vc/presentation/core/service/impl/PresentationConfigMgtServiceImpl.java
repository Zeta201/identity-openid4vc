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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.PresentationCoreConstants;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.internal.PresentationCoreDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationConfigMgtService;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreAuditLogger;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreExceptionHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;

/**
 * {@link ConfigurationManager}-backed implementation of {@link PresentationConfigMgtService}.
 * Reads with {@code inherited=true} so sub-organizations automatically fall back
 * to the root organization's configuration when no explicit configuration has been saved.
 */
public class PresentationConfigMgtServiceImpl implements PresentationConfigMgtService {

    private static final Log LOG = LogFactory.getLog(PresentationConfigMgtServiceImpl.class);
    private static final PresentationCoreAuditLogger AUDIT_LOGGER = PresentationCoreAuditLogger.getInstance();

    static final String VP_CONFIG_RESOURCE_TYPE_NAME = "OPENID4VP_CONFIG";
    static final String VP_CONFIG_RESOURCE_NAME = "OPENID4VP_CONFIGURATION";

    private static final String PROP_CLIENT_ID_SCHEME = "clientIdScheme";
    private static final String PROP_RESPONSE_MODE = "responseMode";

    @Override
    public VPTenantConfig getVPConfig(String tenantDomain) throws PresentationCoreException {

        try {
            Resource resource = fetchVPConfigResource();
            if (resource == null || resource.getAttributes() == null) {
                return new VPTenantConfig(
                    PresentationCoreConstants.DEFAULT_CLIENT_ID_SCHEME, 
                    PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT);
            }
            Map<String, String> attributeMap = resource.getAttributes().stream()
                    .collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
            VPTenantConfig config = new VPTenantConfig();
            config.setClientIdScheme(attributeMap.get(PROP_CLIENT_ID_SCHEME));
            config.setResponseMode(attributeMap.get(PROP_RESPONSE_MODE));
            return config;
        } catch (ConfigurationManagementException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.CONFIG_RETRIEVAL_ERROR, e);
        }
    }

    @Override
    public void setVPConfig(VPTenantConfig config, String tenantDomain) throws PresentationCoreException {

        try {
            List<Attribute> attributes = new ArrayList<>();
            addAttribute(attributes, PROP_CLIENT_ID_SCHEME, config.getClientIdScheme());
            addAttribute(attributes, PROP_RESPONSE_MODE, config.getResponseMode());
            ResourceAdd resourceAdd = new ResourceAdd();
            resourceAdd.setName(VP_CONFIG_RESOURCE_NAME);
            resourceAdd.setAttributes(attributes);
            getConfigurationManager().replaceResource(VP_CONFIG_RESOURCE_TYPE_NAME, resourceAdd);
            AUDIT_LOGGER.logVPConfigUpdated(config, tenantDomain);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Saved VP config for " + tenantDomain
                        + ": clientIdScheme=" + config.getClientIdScheme()
                        + " responseMode=" + config.getResponseMode());
            }
        } catch (ConfigurationManagementException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.CONFIG_UPDATE_ERROR, e);
        }
    }

    private Resource fetchVPConfigResource() throws ConfigurationManagementException {

        try {
            return getConfigurationManager().getResource(
                    VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return null;
            }
            throw e;
        }
    }

    private void addAttribute(List<Attribute> attributes, String key, String value) {

        if (value != null) {
            Attribute attribute = new Attribute();
            attribute.setKey(key);
            attribute.setValue(value);
            attributes.add(attribute);
        }
    }

    private ConfigurationManager getConfigurationManager() {

        return PresentationCoreDataHolder.getInstance().getConfigurationManager();
    }
}
