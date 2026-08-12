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

package org.wso2.carbon.identity.openid4vc.presentation.management.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Distributed cache for presentation definitions, keyed by tenant domain and definition ID.
 * Entries are invalidated explicitly on update or delete of a definition.
 */
public class PresentationDefinitionCache
        extends BaseCache<PresentationDefinitionCacheKey, PresentationDefinitionCacheEntry> {

    private static final String CACHE_NAME = "OpenID4VPPresentationDefinitionCache";

    private static PresentationDefinitionCache instance;

    private PresentationDefinitionCache() {

        super(CACHE_NAME);
    }

    public static PresentationDefinitionCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            instance = new PresentationDefinitionCache();
        }
        return instance;
    }

    public void put(String tenantDomain, PresentationDefinition definition) {

        addToCache(new PresentationDefinitionCacheKey(tenantDomain, definition.getDefinitionId()),
                new PresentationDefinitionCacheEntry(definition),
                tenantDomain);
    }

    public PresentationDefinition get(String tenantDomain, String definitionId) {

        PresentationDefinitionCacheEntry entry = getValueFromCache(
                new PresentationDefinitionCacheKey(tenantDomain, definitionId),
                tenantDomain);
        return entry != null ? entry.getDefinition() : null;
    }

    public void remove(String tenantDomain, String definitionId) {

        clearCacheEntry(new PresentationDefinitionCacheKey(tenantDomain, definitionId),
                tenantDomain);
    }
}
