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

package org.wso2.carbon.identity.openid4vc.template.management.cache;

import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key for {@link PresentationDefinitionCacheByIdentifier}, keyed by the identifier.
 */
public class PresentationDefinitionIdentifierCacheKey extends CacheKey {

    private static final long serialVersionUID = 1L;

    private final String identifier;

    public PresentationDefinitionIdentifierCacheKey(String identifier) {

        this.identifier = identifier;
    }

    public String getIdentifier() {

        return identifier;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof PresentationDefinitionIdentifierCacheKey)) {
            return false;
        }
        return identifier.equals(((PresentationDefinitionIdentifierCacheKey) o).getIdentifier());
    }

    @Override
    public int hashCode() {

        return identifier.hashCode();
    }
}
