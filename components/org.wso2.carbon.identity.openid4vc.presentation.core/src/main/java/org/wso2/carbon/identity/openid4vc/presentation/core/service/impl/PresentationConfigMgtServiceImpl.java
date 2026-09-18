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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
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
 * Reads with {@code inherited=true} so sub-organizations automatically fall back to the root
 * organization's configuration when no explicit configuration has been saved.
 */
public class PresentationConfigMgtServiceImpl implements PresentationConfigMgtService {

    private static final Log LOG = LogFactory.getLog(PresentationConfigMgtServiceImpl.class);
    private static final PresentationCoreAuditLogger AUDIT_LOGGER = PresentationCoreAuditLogger.getInstance();

    static final String VP_CONFIG_RESOURCE_TYPE_NAME = "OPENID4VP_CONFIG";
    static final String VP_CONFIG_RESOURCE_NAME = "OPENID4VP_CONFIGURATION";

    private static final String PROP_CLIENT_ID_SCHEME = "clientIdScheme";
    private static final String PROP_RESPONSE_MODE = "responseMode";

    /**
     * Retrieves the VP tenant configuration for the given tenant domain.
     *
     * <p>When no resource exists, returns a config populated entirely from defaults via
     * {@link #setDefaultConfigValues(VPTenantConfig)}.
     *
     * @param tenantDomain the tenant domain whose configuration to retrieve
     * @return the VP tenant configuration, never {@code null}
     * @throws PresentationCoreException if the configuration store cannot be read
     */
    @Override
    public VPTenantConfig getVPConfig(String tenantDomain) throws PresentationCoreException {

        try {
            // Fetch the raw resource from the config store; null if not yet saved.
            Resource resource = fetchVPConfigResource();
            // Construct a blank DTO to hold the resolved config values.
            VPTenantConfig config = new VPTenantConfig();
            if (resource != null && resource.getAttributes() != null) {
                // Index all stored attributes by key for O(1) lookup.
                Map<String, String> attributeMap = resource.getAttributes().stream()
                        .collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
                // Map each stored attribute into the typed config fields.
                config.setClientIdScheme(attributeMap.get(PROP_CLIENT_ID_SCHEME));
                config.setResponseMode(attributeMap.get(PROP_RESPONSE_MODE));
            }
            // Fill any blank fields with server defaults before returning.
            setDefaultConfigValues(config);
            return config;
        } catch (ConfigurationManagementException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.CONFIG_RETRIEVAL_ERROR, e);
        }
    }

    /**
     * Fills in any blank VP config fields with their server defaults.
     *
     * @param config the config object to mutate in-place
     */
    private void setDefaultConfigValues(VPTenantConfig config) {

        // Fall back to the server default when clientIdScheme was not explicitly configured.
        if (StringUtils.isBlank(config.getClientIdScheme())) {
            config.setClientIdScheme(Constants.DEFAULT_CLIENT_ID_SCHEME);
        }
        // Fall back to the server default when responseMode was not explicitly configured.
        if (StringUtils.isBlank(config.getResponseMode())) {
            config.setResponseMode(PresentationCoreConstants.DEFAULT_RESPONSE_MODE);
        }
    }

    /**
     * Persists the VP tenant configuration for the given tenant domain.
     *
     * <p>Uses a full replace so any attribute omitted from {@code config} is removed from the store.
     *
     * @param config       the new configuration to persist
     * @param tenantDomain the tenant domain whose configuration to update
     * @throws PresentationCoreException if the configuration store cannot be written
     */
    @Override
    public void setVPConfig(VPTenantConfig config, String tenantDomain) throws PresentationCoreException {

        try {
            // Build the flat attribute list for the config store.
            List<Attribute> attributes = new ArrayList<>();
            // Add each field only if a value was supplied.
            addAttribute(attributes, PROP_CLIENT_ID_SCHEME, config.getClientIdScheme());
            addAttribute(attributes, PROP_RESPONSE_MODE, config.getResponseMode());
            // Wrap the attribute list into the resource envelope.
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

    /**
     * Loads the VP config resource from the configuration store, returning {@code null}
     * when the resource has not yet been saved.
     *
     * @return the resource, or {@code null} if it does not exist
     * @throws ConfigurationManagementException if a store error other than not-found occurs
     */
    private Resource fetchVPConfigResource() throws ConfigurationManagementException {

        try {
            // Attempt to load the resource, passing inherited=true so sub-orgs fall back to parent tenant.
            return getConfigurationManager().getResource(
                    VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true);
        } catch (ConfigurationManagementException e) {
            // Treat "resource does not exist" as an uninitialized config, not an error.
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return null;
            }
            // Re-throw any other config store error to the caller.
            throw e;
        }
    }

    /**
     * Appends a key-value attribute to the list, skipping the entry when {@code value} is {@code null}.
     *
     * @param attributes the list to append to
     * @param key        the attribute key
     * @param value      the attribute value; {@code null} entries are silently omitted
     */
    private void addAttribute(List<Attribute> attributes, String key, String value) {

        // Skip null values to avoid storing empty attributes in the config store.
        if (value != null) {
            Attribute attribute = new Attribute();
            attribute.setKey(key);
            attribute.setValue(value);
            // Append the populated attribute to the list.
            attributes.add(attribute);
        }
    }

    /**
     * Returns the {@link ConfigurationManager} from the OSGi service holder.
     *
     * @return the configuration manager
     */
    private ConfigurationManager getConfigurationManager() {

        return PresentationCoreDataHolder.getInstance().getConfigurationManager();
    }
}
