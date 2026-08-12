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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Distributed cache for per-tenant OpenID4VP configuration.
 * Entries are invalidated explicitly whenever {@code setConfig} is called.
 */
public class OpenID4VPTenantConfigCache
        extends BaseCache<OpenID4VPTenantConfigCacheKey, OpenID4VPTenantConfigCacheEntry> {

    private static final String CACHE_NAME = "OpenID4VPTenantConfigCache";

    private static OpenID4VPTenantConfigCache instance;

    private OpenID4VPTenantConfigCache() {

        super(CACHE_NAME);
    }

    public static OpenID4VPTenantConfigCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            instance = new OpenID4VPTenantConfigCache();
        }
        return instance;
    }

    public void put(String tenantDomain, VPConfigService.TenantConfig config) {

        addToCache(new OpenID4VPTenantConfigCacheKey(tenantDomain),
                new OpenID4VPTenantConfigCacheEntry(config),
                tenantDomain);
    }

    public VPConfigService.TenantConfig get(String tenantDomain) {

        OpenID4VPTenantConfigCacheEntry entry = getValueFromCache(
                new OpenID4VPTenantConfigCacheKey(tenantDomain),
                tenantDomain);
        return entry != null ? entry.getConfig() : null;
    }

    public void remove(String tenantDomain) {

        clearCacheEntry(new OpenID4VPTenantConfigCacheKey(tenantDomain),
                tenantDomain);
    }
}
