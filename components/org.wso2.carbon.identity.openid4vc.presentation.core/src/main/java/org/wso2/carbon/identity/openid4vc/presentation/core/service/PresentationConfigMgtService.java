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
 * This interface manages per-tenant VP configuration.
 */
public interface PresentationConfigMgtService {

    /**
     * Retrieves the VP configuration for the given tenant.
     *
     * @param tenantDomain Tenant domain whose config should be retrieved.
     * @return Current VP config; individual fields may be null if unset.
     * @throws PresentationCoreException If the registry lookup fails.
     */
    VPTenantConfig getVPConfig(String tenantDomain) throws PresentationCoreException;

    /**
     * Persists the VP configuration for the given tenant.
     *
     * @param vpConfig     New config values to store.
     * @param tenantDomain Tenant domain whose config should be updated.
     * @throws PresentationCoreException If the registry write fails.
     */
    void setVPConfig(VPTenantConfig vpConfig, String tenantDomain) throws PresentationCoreException;
}
