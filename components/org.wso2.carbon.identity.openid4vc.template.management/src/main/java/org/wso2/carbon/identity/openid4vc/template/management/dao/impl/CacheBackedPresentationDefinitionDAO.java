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

package org.wso2.carbon.identity.openid4vc.template.management.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.openid4vc.template.management.cache.PresentationDefinitionCacheById;
import org.wso2.carbon.identity.openid4vc.template.management.cache.PresentationDefinitionCacheByIdentifier;
import org.wso2.carbon.identity.openid4vc.template.management.cache.PresentationDefinitionCacheEntry;
import org.wso2.carbon.identity.openid4vc.template.management.cache.PresentationDefinitionIdCacheKey;
import org.wso2.carbon.identity.openid4vc.template.management.cache.PresentationDefinitionIdentifierCacheKey;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.ConnectedIdpInfo;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.util.List;

/**
 * Cache-backed implementation of {@link PresentationDefinitionDAO}.
 * Wraps an underlying DAO and adds caching for single-definition lookups by ID and by identifier.
 */
public class CacheBackedPresentationDefinitionDAO implements PresentationDefinitionDAO {

    private static final Log LOG = LogFactory.getLog(CacheBackedPresentationDefinitionDAO.class);

    private final PresentationDefinitionDAO presentationDefinitionDAO;
    private final PresentationDefinitionCacheById presentationDefinitionCacheById;
    private final PresentationDefinitionCacheByIdentifier presentationDefinitionCacheByIdentifier;

    public CacheBackedPresentationDefinitionDAO(PresentationDefinitionDAO presentationDefinitionDAO) {

        this.presentationDefinitionDAO = presentationDefinitionDAO;
        presentationDefinitionCacheById = PresentationDefinitionCacheById.getInstance();
        presentationDefinitionCacheByIdentifier = PresentationDefinitionCacheByIdentifier.getInstance();
    }

    @Override
    public void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws PresentationManagementException {

        presentationDefinitionDAO.createPresentationDefinition(presentationDefinition);
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationManagementException {

        PresentationDefinitionIdCacheKey cacheKey = new PresentationDefinitionIdCacheKey(definitionId);
        PresentationDefinitionCacheEntry entry =
                presentationDefinitionCacheById.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for presentation definition " + definitionId);
            }
            return entry.getDefinition();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for presentation definition " + definitionId
                    + ". Fetching entry from DB");
        }

        PresentationDefinition definition =
                presentationDefinitionDAO.getPresentationDefinitionById(definitionId, tenantId);

        if (definition != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry fetched from DB for presentation definition " + definitionId
                        + ". Updating cache");
            }
            addToAllCaches(definition, tenantId);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry for presentation definition " + definitionId
                        + " not found in cache or DB");
            }
        }

        return definition;
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByIdentifier(String identifier, int tenantId)
            throws PresentationManagementException {

        PresentationDefinitionIdentifierCacheKey cacheKey =
                new PresentationDefinitionIdentifierCacheKey(identifier);
        PresentationDefinitionCacheEntry entry =
                presentationDefinitionCacheByIdentifier.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for presentation definition identifier " + identifier);
            }
            return entry.getDefinition();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for presentation definition identifier " + identifier
                    + ". Fetching entry from DB");
        }

        PresentationDefinition definition =
                presentationDefinitionDAO.getPresentationDefinitionByIdentifier(identifier, tenantId);

        if (definition != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry fetched from DB for presentation definition identifier " + identifier
                        + ". Updating cache");
            }
            addToAllCaches(definition, tenantId);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Entry for presentation definition identifier " + identifier
                        + " not found in cache or DB");
            }
        }

        return definition;
    }

    @Override
    public boolean presentationDefinitionIdentifierExists(String identifier, int tenantId)
            throws PresentationManagementException {

        PresentationDefinitionIdentifierCacheKey cacheKey =
                new PresentationDefinitionIdentifierCacheKey(identifier);
        PresentationDefinitionCacheEntry entry =
                presentationDefinitionCacheByIdentifier.getValueFromCache(cacheKey, tenantId);

        if (entry != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cache entry found for presentation definition identifier " + identifier);
            }
            return true;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cache entry not found for presentation definition identifier " + identifier
                    + ". Fetching entry from DB");
        }

        return presentationDefinitionDAO.presentationDefinitionIdentifierExists(identifier, tenantId);
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws PresentationManagementException {

        return presentationDefinitionDAO.getAllPresentationDefinitions(tenantId);
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationManagementException {

        clearAllCaches(definitionId, tenantId);
        presentationDefinitionDAO.deletePresentationDefinition(definitionId, tenantId);
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws PresentationManagementException {

        return presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId);
    }

    @Override
    public List<PresentationDefinition> list(Integer limit, Integer tenantId, String sortOrder,
            List<ExpressionNode> expressionNodes) throws PresentationManagementException {

        return presentationDefinitionDAO.list(limit, tenantId, sortOrder, expressionNodes);
    }

    @Override
    public boolean isDefinitionInUse(String definitionId, int tenantId)
            throws PresentationManagementException {

        return presentationDefinitionDAO.isDefinitionInUse(definitionId, tenantId);
    }

    @Override
    public List<ConnectedIdpInfo> getConnectedIdps(String definitionId, int tenantId)
            throws PresentationManagementException {

        return presentationDefinitionDAO.getConnectedIdps(definitionId, tenantId);
    }

    @Override
    public void removeStaleIdpClaimMappings(String definitionId, List<String> staleClaimPaths, int tenantId)
            throws PresentationManagementException {

        presentationDefinitionDAO.removeStaleIdpClaimMappings(definitionId, staleClaimPaths, tenantId);
    }

    @Override
    public void updatePresentationDefinition(PresentationDefinition presentationDefinition,
            List<String> staleClaimPaths, int tenantId) throws PresentationManagementException {

        clearAllCaches(presentationDefinition.getDefinitionId(), tenantId);
        presentationDefinitionDAO.updatePresentationDefinition(presentationDefinition, staleClaimPaths, tenantId);
    }

    @Override
    public Integer getDefinitionsCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws PresentationManagementException {

        return presentationDefinitionDAO.getDefinitionsCount(tenantId, expressionNodes);
    }

    private void addToAllCaches(PresentationDefinition definition, int tenantId) {

        PresentationDefinitionCacheEntry cacheEntry = new PresentationDefinitionCacheEntry(definition);

        if (definition.getDefinitionId() != null) {
            presentationDefinitionCacheById.addToCache(
                    new PresentationDefinitionIdCacheKey(definition.getDefinitionId()), cacheEntry, tenantId);
        }
        if (definition.getIdentifier() != null) {
            presentationDefinitionCacheByIdentifier.addToCache(
                    new PresentationDefinitionIdentifierCacheKey(definition.getIdentifier()), cacheEntry, tenantId);
        }
    }

    private void clearAllCaches(String definitionId, int tenantId) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing cache entries for presentation definition " + definitionId
                    + " of tenantId: " + tenantId);
        }

        PresentationDefinitionIdCacheKey idKey = new PresentationDefinitionIdCacheKey(definitionId);
        PresentationDefinitionCacheEntry entry = presentationDefinitionCacheById.getValueFromCache(idKey, tenantId);

        presentationDefinitionCacheById.clearCacheEntry(idKey, tenantId);

        if (entry != null && entry.getDefinition().getIdentifier() != null) {
            presentationDefinitionCacheByIdentifier.clearCacheEntry(
                    new PresentationDefinitionIdentifierCacheKey(entry.getDefinition().getIdentifier()), tenantId);
        }
    }
}
