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

package org.wso2.carbon.identity.openid4vc.presentation.core.cache;

import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key for {@link VPSessionCache}, keyed by VP request ID.
 */
public class VPSessionCacheKey extends CacheKey {

    private static final long serialVersionUID = 4823649182736451892L;

    private String requestId;

    public VPSessionCacheKey(String requestId) {

        this.requestId = requestId;
    }

    public String getRequestId() {

        return requestId;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass() || !super.equals(o)) {
            return false;
        }
        VPSessionCacheKey that = (VPSessionCacheKey) o;
        return requestId.equals(that.requestId);
    }

    @Override
    public int hashCode() {

        return requestId.hashCode();
    }
}
