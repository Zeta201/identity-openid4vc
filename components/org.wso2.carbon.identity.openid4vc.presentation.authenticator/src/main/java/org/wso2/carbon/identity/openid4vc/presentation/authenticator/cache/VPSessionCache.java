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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.store.VPSessionStore;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/**
 * Two-tier cache for VP flow sessions.
 *
 * <p><b>Tier 1 — in-process (JCache/Hazelcast):</b> {@link BaseCache} provides a fast
 * node-local store. In Hazelcast-enabled clusters this is already distributed; in
 * single-node or non-Hazelcast deployments it is purely in-memory.</p>
 *
 * <p><b>Tier 2 — database ({@code IDN_VP_SESSION_STORE}):</b> {@link VPSessionStore}
 * persists every session to the IS session database. On a local-cache miss (i.e. the
 * request landed on a different pod than the one that created the session), the DB is
 * queried and the result is back-filled into the local cache for subsequent reads.</p>
 *
 * <p>This design serves all three VP flows — wallet authentication, self-registration
 * (VP executor), and standalone credential verification — from the same consistent
 * store without relying on the IS authentication-context cache.</p>
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

    /**
     * Stores a VP session in both the local cache and the database.
     * Called on session creation (initiate) and on every status update
     * (e.g. when the wallet submits its response).
     *
     * @param requestId the VP session identifier
     * @param session   the session to store
     */
    public void put(String requestId, VPFlowSession session) {

        addToCache(new VPSessionCacheKey(requestId), new VPSessionCacheEntry(session),
                MultitenantConstants.SUPER_TENANT_ID);
        VPSessionStore.getInstance().put(requestId, session);
    }

    /**
     * Retrieves a VP session, checking the local cache first and falling back
     * to the database on a miss.
     * Returns {@code null} if the session is not found or has expired.
     *
     * @param requestId the VP session identifier
     * @return the session, or {@code null}
     */
    public VPFlowSession get(String requestId) {

        if (requestId == null) {
            return null;
        }

        VPSessionCacheEntry entry = getValueFromCache(new VPSessionCacheKey(requestId),
                MultitenantConstants.SUPER_TENANT_ID);

        VPFlowSession session = (entry != null) ? entry.getSession() : null;

        if (session == null) {
            // Local-cache miss — query DB (request came to a different pod).
            session = VPSessionStore.getInstance().get(requestId);
            if (session != null) {
                // Back-fill local cache so subsequent reads on this pod are fast.
                addToCache(new VPSessionCacheKey(requestId), new VPSessionCacheEntry(session),
                        MultitenantConstants.SUPER_TENANT_ID);
            }
        }

        if (session == null) {
            return null;
        }

        if (System.currentTimeMillis() > session.getExpiresAt()) {
            remove(requestId);
            return null;
        }

        return session;
    }

    /**
     * Removes a VP session from both the local cache and the database.
     *
     * @param requestId the VP session identifier
     */
    public void remove(String requestId) {

        clearCacheEntry(new VPSessionCacheKey(requestId), MultitenantConstants.SUPER_TENANT_ID);
        VPSessionStore.getInstance().remove(requestId);
    }
}
