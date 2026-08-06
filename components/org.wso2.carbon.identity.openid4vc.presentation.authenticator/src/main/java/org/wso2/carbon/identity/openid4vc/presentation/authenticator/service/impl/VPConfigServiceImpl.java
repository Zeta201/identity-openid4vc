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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.OpenID4VPTenantConfigCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;

/**
 * Governance-registry-backed implementation of {@link VPConfigService}.
 * Stores per-tenant config at {@value #REGISTRY_PATH} in the governance registry.
 */
public class VPConfigServiceImpl implements VPConfigService {

    private static final Log LOG = LogFactory.getLog(VPConfigServiceImpl.class);

    static final String REGISTRY_PATH = "identity/openid4vp/config";

    private static final String PROP_CLIENT_ID_SCHEME = "clientIdScheme";
    private static final String PROP_RESPONSE_MODE = "responseMode";

    @Override
    public VPConfigService.TenantConfig getConfig(String tenantDomain) throws VPAuthenticatorException {

        VPConfigService.TenantConfig cached = OpenID4VPTenantConfigCache.getInstance().get(tenantDomain);
        if (cached != null) {
            return cached;
        }

        VPConfigService.TenantConfig config = new VPConfigService.TenantConfig();
        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            if (!registry.resourceExists(REGISTRY_PATH)) {
                OpenID4VPTenantConfigCache.getInstance().put(tenantDomain, config);
                return config;
            }
            Resource resource = registry.get(REGISTRY_PATH);
            config.setClientIdScheme(resource.getProperty(PROP_CLIENT_ID_SCHEME));
            config.setResponseMode(resource.getProperty(PROP_RESPONSE_MODE));
        } catch (RegistryException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.CONFIG_RETRIEVAL_ERROR,
                    "Failed to retrieve VP config for tenant: " + tenantDomain, e);
        }
        OpenID4VPTenantConfigCache.getInstance().put(tenantDomain, config);
        return config;
    }

    @Override
    public void setConfig(VPConfigService.TenantConfig config, String tenantDomain)
            throws VPAuthenticatorException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            Resource resource;
            if (registry.resourceExists(REGISTRY_PATH)) {
                resource = registry.get(REGISTRY_PATH);
            } else {
                resource = registry.newResource();
            }
            setOrClear(resource, PROP_CLIENT_ID_SCHEME, config.getClientIdScheme());
            setOrClear(resource, PROP_RESPONSE_MODE, config.getResponseMode());
            registry.put(REGISTRY_PATH, resource);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Saved tenant config for " + tenantDomain.replace("\r", "").replace("\n", "")
                        + ": clientIdScheme=" + config.getClientIdScheme()
                        + " responseMode=" + config.getResponseMode());
            }
        } catch (RegistryException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.CONFIG_UPDATE_ERROR,
                    "Failed to persist VP config for tenant: " + tenantDomain, e);
        }
        OpenID4VPTenantConfigCache.getInstance().remove(tenantDomain);
    }

    @Override
    public VPConfigService.TenantConfig getConfigByTenantId(int tenantId) throws VPAuthenticatorException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        return getConfig(tenantDomain);
    }

    /**
     * Returns the governance system registry for the given tenant domain.
     *
     * @param tenantDomain the tenant domain whose governance registry should be returned
     * @return the governance {@link Registry} for the tenant
     * @throws RegistryException if the registry service is unavailable or the tenant cannot be resolved
     */
    private Registry getGovernanceRegistry(String tenantDomain) throws RegistryException {

        RegistryService registryService = IdentityTenantUtil.getRegistryService();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return registryService.getGovernanceSystemRegistry(tenantId);
    }

    /**
     * Sets the given property on the registry resource if {@code value} is non-null,
     * or removes the property if {@code value} is {@code null}.
     *
     * @param resource the registry resource to update
     * @param key      the property key to set or remove
     * @param value    the value to set, or {@code null} to remove the property
     */
    private void setOrClear(Resource resource, String key, String value) {

        if (value != null) {
            resource.setProperty(key, value);
        } else {
            resource.removeProperty(key);
        }
    }
}
