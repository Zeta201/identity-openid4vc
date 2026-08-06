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

import org.wso2.carbon.identity.core.cache.CacheKey;

import java.io.Serial;
import java.util.Objects;

/**
 * Cache key for {@link PresentationDefinitionCache}, keyed by tenant domain and definition ID.
 */
public class PresentationDefinitionCacheKey extends CacheKey {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String tenantDomain;
    private final String definitionId;

    public PresentationDefinitionCacheKey(String tenantDomain, String definitionId) {

        this.tenantDomain = tenantDomain;
        this.definitionId = definitionId;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public String getDefinitionId() {

        return definitionId;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof PresentationDefinitionCacheKey)) {
            return false;
        }
        PresentationDefinitionCacheKey other = (PresentationDefinitionCacheKey) o;
        return Objects.equals(tenantDomain, other.tenantDomain)
                && Objects.equals(definitionId, other.definitionId);
    }

    @Override
    public int hashCode() {

        return Objects.hash(tenantDomain, definitionId);
    }
}
