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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;

/**
 * {@link ConfigurationManager}-backed implementation of {@link VPConfigService}.
 * Reads with {@code inherited=true} so sub-organizations automatically fall back
 * to the root organization's configuration when no explicit configuration has been saved.
 */
public class VPConfigServiceImpl implements VPConfigService {

    private static final Log LOG = LogFactory.getLog(VPConfigServiceImpl.class);

    static final String VP_CONFIG_RESOURCE_TYPE_NAME = "OPENID4VP_CONFIG";
    static final String VP_CONFIG_RESOURCE_NAME = "OPENID4VP_CONFIGURATION";

    private static final String PROP_CLIENT_ID_SCHEME = "clientIdScheme";
    private static final String PROP_RESPONSE_MODE = "responseMode";

    @Override
    public VPConfigService.TenantConfig getConfig(String tenantDomain) throws VPAuthenticatorException {

        try {
            Resource resource = getResource(VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true);
            if (resource == null || resource.getAttributes() == null) {
                return new VPConfigService.TenantConfig();
            }
            Map<String, String> attributeMap = resource.getAttributes().stream()
                    .collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
            VPConfigService.TenantConfig config = new VPConfigService.TenantConfig();
            config.setClientIdScheme(attributeMap.get(PROP_CLIENT_ID_SCHEME));
            config.setResponseMode(attributeMap.get(PROP_RESPONSE_MODE));
            return config;
        } catch (ConfigurationManagementException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.CONFIG_RETRIEVAL_ERROR,
                    "Failed to retrieve VP config for tenant: " + tenantDomain, e);
        }
    }

    @Override
    public void setConfig(VPConfigService.TenantConfig config, String tenantDomain) throws VPAuthenticatorException {

        try {
            List<Attribute> attributes = new ArrayList<>();
            addAttribute(attributes, PROP_CLIENT_ID_SCHEME, config.getClientIdScheme());
            addAttribute(attributes, PROP_RESPONSE_MODE, config.getResponseMode());
            ResourceAdd resourceAdd = new ResourceAdd();
            resourceAdd.setName(VP_CONFIG_RESOURCE_NAME);
            resourceAdd.setAttributes(attributes);
            getConfigurationManager().replaceResource(VP_CONFIG_RESOURCE_TYPE_NAME, resourceAdd);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Saved VP config for " + tenantDomain
                        + ": clientIdScheme=" + config.getClientIdScheme()
                        + " responseMode=" + config.getResponseMode());
            }
        } catch (ConfigurationManagementException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.CONFIG_UPDATE_ERROR,
                    "Failed to persist VP config for tenant: " + tenantDomain, e);
        }
    }

    @Override
    public VPConfigService.TenantConfig getConfigByTenantId(int tenantId) throws VPAuthenticatorException {

        return getConfig(IdentityTenantUtil.getTenantDomain(tenantId));
    }

    private Resource getResource(String resourceTypeName, String resourceName, boolean inherited)
            throws ConfigurationManagementException {

        try {
            if (getConfigurationManager() != null) {
                return getConfigurationManager().getResource(resourceTypeName, resourceName, inherited);
            }
            return null;
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return null;
            } else {
                throw e;
            }
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

        return VPDataHolder.getConfigurationManager();
    }
}
