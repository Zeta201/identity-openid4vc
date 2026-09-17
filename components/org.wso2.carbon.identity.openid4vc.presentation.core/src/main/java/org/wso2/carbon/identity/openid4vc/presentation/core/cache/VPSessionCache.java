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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.identity.openid4vc.presentation.core.store.VPSessionStore;

import java.sql.SQLException;

/**
 * Cache for {@link VPSession}.
 */
public class VPSessionCache extends BaseCache<VPSessionCacheKey, VPSessionCacheEntry> {

    private static final Log log = LogFactory.getLog(VPSessionCache.class);
    private static final String CACHE_NAME = "VPSessionCache";
    private static volatile VPSessionCache instance;

    private VPSessionCache() {

        super(CACHE_NAME);
    }

    public static VPSessionCache getInstance() {

        if (instance == null) {
            synchronized (VPSessionCache.class) {
                if (instance == null) {
                    instance = new VPSessionCache();
                }
            }
        }
        return instance;
    }

    @Override
    public void addToCache(VPSessionCacheKey key, VPSessionCacheEntry entry, int tenantId) {

        super.addToCache(key, entry, tenantId);
        try {
            VPSessionStore.getInstance().put(key.getRequestId(), entry.getSession());
        } catch (CryptoException e) {
            log.error("Failed to encrypt VP session secrets for requestId: " + key.getRequestId(), e);
        } catch (SQLException e) {
            log.error("Failed to persist VP session for requestId: " + key.getRequestId(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Cache entry added for VP session: " + key.getRequestId());
        }
    }

    @Override
    public VPSessionCacheEntry getValueFromCache(VPSessionCacheKey key, int tenantId) {

        VPSessionCacheEntry entry = super.getValueFromCache(key, tenantId);
        if (entry == null) {
            try {
                VPSession session = VPSessionStore.getInstance().get(key.getRequestId());
                if (session != null) {
                    entry = new VPSessionCacheEntry(session);
                    super.addToCache(key, entry, tenantId);
                }
            } catch (CryptoException | SQLException e) {
                log.error("Failed to retrieve VP session from store for requestId: " + key.getRequestId(), e);
            }
        }
        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry not found for VP session: " + key.getRequestId());
            }
        }
        return entry;
    }

    @Override
    public void clearCacheEntry(VPSessionCacheKey key, int tenantId) {

        super.clearCacheEntry(key, tenantId);
        VPSessionStore.getInstance().remove(key.getRequestId());
        if (log.isDebugEnabled()) {
            log.debug("Cache entry cleared for VP session: " + key.getRequestId());
        }
    }

}
