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

package org.wso2.carbon.identity.openid4vc.presentation.core.service;

import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPTenantConfig;

/**
 * OSGi service for per-tenant VP configuration management.
 * Config is persisted in the governance registry under each tenant's namespace.
 */
public interface PresentationConfigMgtService {

    /**
     * Retrieves the VP configuration for the given tenant.
     * Returns an object with {@code null} fields if no tenant-level config has been saved yet.
     *
     * @param tenantDomain the tenant domain whose config should be retrieved
     * @return the current VP config; never {@code null}, but individual fields may be {@code null}
     * @throws PresentationCoreException if the registry lookup fails
     */
    VPTenantConfig getVPConfig(String tenantDomain) throws PresentationCoreException;

    /**
     * Persists the VP configuration for the given tenant.
     * Any existing config for the tenant is overwritten.
     *
     * @param vpConfig     the new config values to store
     * @param tenantDomain the tenant domain whose config should be updated
     * @throws PresentationCoreException if the registry write fails
     */
    void setVPConfig(VPTenantConfig vpConfig, String tenantDomain) throws PresentationCoreException;
}
