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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;

import java.io.Serializable;

/**
 * OSGi service for per-tenant VP configuration management.
 * Config is persisted in the governance registry under each tenant's namespace.
 */
public interface VPConfigService {

    /**
     * Retrieves the VP configuration for the given tenant.
     * Returns an object with {@code null} fields if no tenant-level config has been saved yet.
     *
     * @param tenantDomain the tenant domain whose config should be retrieved
     * @return the current tenant config; never {@code null}, but individual fields may be {@code null}
     * @throws VPAuthenticatorException if the registry lookup fails
     */
    TenantConfig getConfig(String tenantDomain) throws VPAuthenticatorException;

    /**
     * Retrieves the VP configuration by tenant ID.
     * Resolves the tenant domain from the given ID before performing the registry lookup.
     *
     * @param tenantId the numeric identifier of the tenant
     * @return the current tenant config; never {@code null}, but individual fields may be {@code null}
     * @throws VPAuthenticatorException if the tenant ID cannot be resolved or the registry lookup fails
     */
    TenantConfig getConfigByTenantId(int tenantId) throws VPAuthenticatorException;

    /**
     * Persists the VP configuration for the given tenant.
     * Any existing config for the tenant is overwritten.
     *
     * @param config       the new config values to store
     * @param tenantDomain the tenant domain whose config should be updated
     * @throws VPAuthenticatorException if the registry write fails
     */
    void setConfig(TenantConfig config, String tenantDomain) throws VPAuthenticatorException;

    /**
     * Per-tenant VP configuration model.
     * Null fields indicate "not configured" — the server-level default applies.
     */
    class TenantConfig implements Serializable {

        private static final long serialVersionUID = 1L;

        private String clientIdScheme;
        private String responseMode;

        public String getClientIdScheme() {

            return clientIdScheme;
        }

        public void setClientIdScheme(String clientIdScheme) {

            this.clientIdScheme = clientIdScheme;
        }

        public String getResponseMode() {

            return responseMode;
        }

        public void setResponseMode(String responseMode) {

            this.responseMode = responseMode;
        }
    }
}
