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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/**
 * Distributed cache for VP sessions (auth, standalone verification, and self-registration flows).
 * Backed by WSO2's {@link BaseCache} so sessions are visible across all IS cluster nodes.
 * TTL is enforced per-session via the {@code expiresAt} field on {@link VPFlowSession}.
 */
public class VPSessionCache extends BaseCache<VPSessionCacheKey, VPSessionCacheEntry> {

    private static final String CACHE_NAME = "VPSessionCache";

    private static VPSessionCache instance;

    private VPSessionCache() {

        super(CACHE_NAME);
    }

    public static VPSessionCache getInstance() {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            instance = new VPSessionCache();
        }
        return instance;
    }

    public void put(String requestId, VPFlowSession session) {

        addToCache(new VPSessionCacheKey(requestId), new VPSessionCacheEntry(session),
                MultitenantConstants.SUPER_TENANT_ID);
    }

    public VPFlowSession get(String requestId) {

        if (requestId == null) {
            return null;
        }
        VPSessionCacheEntry entry = getValueFromCache(new VPSessionCacheKey(requestId),
                MultitenantConstants.SUPER_TENANT_ID);
        if (entry == null) {
            return null;
        }
        VPFlowSession session = entry.getSession();
        if (session == null) {
            return null;
        }
        if (System.currentTimeMillis() > session.getExpiresAt()) {
            remove(requestId);
            return null;
        }
        return session;
    }

    public void remove(String requestId) {

        clearCacheEntry(new VPSessionCacheKey(requestId), MultitenantConstants.SUPER_TENANT_ID);
    }
}
