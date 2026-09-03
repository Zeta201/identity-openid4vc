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

import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.store.VPSessionStore;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.sql.SQLException;

/**
 * Cache for VP flow sessions, backed by {@link BaseCache} with database fallback via
 * {@link VPSessionStore}. On a cache miss the session is loaded from the database and
 * back-filled into the cache for subsequent reads.
 */
public class VPSessionCache extends BaseCache<VPSessionCacheKey, VPSessionCacheEntry> {

    private static final String CACHE_NAME = "VPSessionCache";

    private static final VPSessionCache instance = new VPSessionCache();

    private VPSessionCache() {

        super(CACHE_NAME);
    }

    public static VPSessionCache getInstance() {

        CarbonUtils.checkSecurity();
        return instance;
    }

    /**
     * Stores a VP session in both the local cache and the database.
     * Called on session creation (initiate) and on every status update
     * (e.g. when the wallet submits its response).
     *
     * @param requestId the VP session identifier
     * @param session   the session to store
     * @throws VPAuthenticatorServerException If session secrets cannot be encrypted or the DB write fails
     */
    public void put(String requestId, VPFlowSession session) throws VPAuthenticatorServerException {

        addToCache(new VPSessionCacheKey(requestId), new VPSessionCacheEntry(session),
                MultitenantConstants.SUPER_TENANT_ID);
        try {
            VPSessionStore.getInstance().put(requestId, session);
        } catch (CryptoException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to encrypt VP session secrets for requestId: " + requestId, e);
        } catch (SQLException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to persist VP session for requestId: " + requestId, e);
        }
    }

    /**
     * Retrieves a VP session, checking the local cache first and falling back
     * to the database on a miss.
     * Returns {@code null} if the session is not found or has expired.
     *
     * @param requestId the VP session identifier
     * @return the session, or {@code null}
     * @throws VPAuthenticatorServerException If the database read or secret decryption fails
     */
    public VPFlowSession get(String requestId) throws VPAuthenticatorServerException {

        if (requestId == null) {
            return null;
        }

        VPSessionCacheEntry entry = getValueFromCache(new VPSessionCacheKey(requestId),
                MultitenantConstants.SUPER_TENANT_ID);

        VPFlowSession session = (entry != null) ? entry.getSession() : null;

        if (session == null) {
            // Local-cache miss — load from DB.
            try {
                session = VPSessionStore.getInstance().get(requestId);
            } catch (CryptoException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to decrypt VP session secrets for requestId: " + requestId, e);
            } catch (SQLException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to retrieve VP session for requestId: " + requestId, e);
            }
            if (session != null) {
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
