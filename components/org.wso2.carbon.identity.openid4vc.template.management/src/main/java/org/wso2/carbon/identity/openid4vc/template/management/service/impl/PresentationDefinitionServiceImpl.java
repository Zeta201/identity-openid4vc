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

package org.wso2.carbon.identity.openid4vc.template.management.service.impl;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.dao.impl.CacheBackedPresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.dao.impl.PresentationDefinitionDAOImpl;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementErrorCode;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.ConnectedIdpInfo;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationClaim;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinitionSearchResult;
import org.wso2.carbon.identity.openid4vc.template.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.template.management.util.Constants;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Implementation of {@link PresentationDefinitionService} for managing presentation definitions.
 */
public class PresentationDefinitionServiceImpl implements PresentationDefinitionService {

    private final PresentationDefinitionDAO presentationDefinitionDAO;

    public PresentationDefinitionServiceImpl() {

        this.presentationDefinitionDAO =
                new CacheBackedPresentationDefinitionDAO(new PresentationDefinitionDAOImpl());
    }

    public PresentationDefinitionServiceImpl(PresentationDefinitionDAO presentationDefinitionDAO) {

        this.presentationDefinitionDAO = presentationDefinitionDAO;
    }

    @Override
    public PresentationDefinition createPresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId)
            throws PresentationManagementException {

        validateForCreate(presentationDefinition);

        String identifier = presentationDefinition.getIdentifier();
        if (presentationDefinitionDAO.presentationDefinitionIdentifierExists(identifier, tenantId)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.DEFINITION_ALREADY_EXISTS,
                    "Presentation definition with identifier already exists: " + identifier);
        }

        String definitionId = UUID.randomUUID().toString();

        PresentationDefinition definitionToCreate = new PresentationDefinition.Builder()
                .id(definitionId)
                .identifier(identifier)
                .displayName(presentationDefinition.getDisplayName())
                .description(presentationDefinition.getDescription())
                .credentials(presentationDefinition.getCredentials())
                .tenantId(tenantId)
                .build();

        presentationDefinitionDAO.createPresentationDefinition(definitionToCreate);
        return definitionToCreate;
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationManagementException {

        if (StringUtils.isBlank(definitionId)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Definition ID is required.");
        }

        PresentationDefinition definition =
                presentationDefinitionDAO.getPresentationDefinitionById(definitionId, tenantId);

        if (definition == null) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.DEFINITION_NOT_FOUND,
                    "Presentation definition not found: " + definitionId);
        }

        return definition;
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws PresentationManagementException {

        return presentationDefinitionDAO.getAllPresentationDefinitions(tenantId);
    }

    @Override
    public PresentationDefinition updatePresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId)
            throws PresentationManagementException {

        String definitionId = presentationDefinition.getId();
        PresentationDefinition existing = getPresentationDefinitionById(definitionId, tenantId);

        List<Credential> updatedCredentials = presentationDefinition.getCredentials() != null
                ? presentationDefinition.getCredentials()
                : existing.getCredentials();
        if (updatedCredentials != null && !updatedCredentials.isEmpty()) {
            validateCredentialIds(updatedCredentials);
        }

        PresentationDefinition definitionToUpdate = new PresentationDefinition.Builder()
                .id(definitionId)
                .identifier(existing.getIdentifier())
                .displayName(StringUtils.isNotBlank(presentationDefinition.getDisplayName())
                        ? presentationDefinition.getDisplayName()
                        : existing.getDisplayName())
                .description(presentationDefinition.getDescription() != null
                        ? presentationDefinition.getDescription()
                        : existing.getDescription())
                .credentials(updatedCredentials)
                .tenantId(tenantId)
                .build();

        List<String> staleClaimPaths = computeStalePaths(existing.getCredentials(), updatedCredentials);
        presentationDefinitionDAO.updatePresentationDefinition(
                definitionToUpdate, staleClaimPaths, tenantId);

        return definitionToUpdate;
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationManagementException {

        getPresentationDefinitionById(definitionId, tenantId);
        if (presentationDefinitionDAO.isDefinitionInUse(definitionId, tenantId)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.DEFINITION_IN_USE,
                    "Presentation definition '" + definitionId +
                            "' is referenced by one or more connections and cannot be deleted.");
        }
        presentationDefinitionDAO.deletePresentationDefinition(definitionId, tenantId);
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws PresentationManagementException {

        return presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId);
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByIdentifier(String identifier, int tenantId)
            throws PresentationManagementException {

        if (StringUtils.isBlank(identifier)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Presentation definition identifier is required.");
        }
        return presentationDefinitionDAO.getPresentationDefinitionByIdentifier(identifier, tenantId);
    }

    @Override
    public PresentationDefinitionSearchResult listWithPagination(String after, String before, Integer limit,
            String filter, String sortOrder, int tenantId) throws PresentationManagementException {

        if (sortOrder != null && !sortOrder.equalsIgnoreCase(Constants.ASC_SORT_ORDER)
                && !sortOrder.equalsIgnoreCase(Constants.DESC_SORT_ORDER)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Invalid sortOrder value '" + sortOrder + "'. Must be ASC or DESC.");
        }
        List<ExpressionNode> expressionNodes =
                PresentationDefinitionFilterUtil.getExpressionNodes(filter, after, before);
        PresentationDefinitionSearchResult searchResult = new PresentationDefinitionSearchResult();
        searchResult.setTotalCount(presentationDefinitionDAO.getDefinitionsCount(tenantId, expressionNodes));
        searchResult.setDefinitions(presentationDefinitionDAO.list(limit, tenantId, sortOrder, expressionNodes));
        return searchResult;
    }

    @Override
    public List<ConnectedIdpInfo> getConnectedIdps(String definitionId, int tenantId)
            throws PresentationManagementException {

        getPresentationDefinitionById(definitionId, tenantId);
        return presentationDefinitionDAO.getConnectedIdps(definitionId, tenantId);
    }

    @Override
    public void replaceIssuerConfigs(String definitionId, String credentialIdentifier,
            List<Issuer> issuerConfigs, int tenantId)
            throws PresentationManagementException {

        if (issuerConfigs == null || issuerConfigs.isEmpty()) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "At least one issuer configuration must be provided for credential '" +
                            credentialIdentifier + "'.");
        }
        if (!presentationDefinitionDAO.presentationDefinitionExists(definitionId, tenantId)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.DEFINITION_NOT_FOUND,
                    "Presentation definition not found: " + definitionId);
        }
        presentationDefinitionDAO.replaceIssuerConfigs(definitionId, credentialIdentifier,
                issuerConfigs, tenantId);
    }

    /**
     * Computes the claim paths that existed in the old requested credentials but are absent in the
     * updated ones. Each path is dot-joined (e.g. {@code "given_name"},
     * {@code "address.street_address"}) to match the remote claim URI stored in
     * {@code IDP_CLAIM.CLAIM} by the admin during attribute mapping.
     *
     * @param oldCredentials the requested credentials before the update
     * @param newCredentials the requested credentials after the update
     * @return the list of dot-joined claim paths that no longer exist after the update
     */
    private List<String> computeStalePaths(List<Credential> oldCredentials,
            List<Credential> newCredentials) {

        Set<String> oldClaimPaths = extractClaimPaths(oldCredentials);
        Set<String> newClaimPaths = extractClaimPaths(newCredentials);
        oldClaimPaths.removeAll(newClaimPaths);
        return new ArrayList<>(oldClaimPaths);
    }

    /**
     * Extracts the set of dot-joined claim paths from the given requested credentials.
     *
     * @param credentials the list of requested credentials to extract paths from; may be null
     * @return the set of dot-joined claim paths across all credentials and their constraints
     */
    private Set<String> extractClaimPaths(List<Credential> credentials) {

        Set<String> claimPaths = new HashSet<>();
        if (credentials == null) {
            return claimPaths;
        }
        for (Credential credential : credentials) {
            if (credential.getClaims() == null) {
                continue;
            }
            for (PresentationClaim constraint : credential.getClaims()) {
                if (constraint.getPath() != null && !constraint.getPath().isEmpty()) {
                    claimPaths.add(constraint.getPath());
                }
            }
        }
        return claimPaths;
    }

    /**
     * Validates that the given presentation definition is suitable for creation.
     * Checks that the definition is non-null, has a valid identifier and non-blank displayName,
     * and that any credential IDs pass the format constraints.
     *
     * @param definition the presentation definition to validate
     * @throws PresentationManagementClientException if any validation rule is violated
     */
    private void validateForCreate(PresentationDefinition definition)
            throws PresentationManagementClientException {

        if (definition == null) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Presentation definition cannot be null.");
        }
        if (StringUtils.isBlank(definition.getIdentifier())) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Presentation definition identifier is required.");
        }
        if (!definition.getIdentifier().matches(Constants.IDENTIFIER_PATTERN)) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Identifier '" + definition.getIdentifier() + "' is invalid. " +
                    "Only alphanumeric characters, underscores, and hyphens are allowed.");
        }
        if (StringUtils.isBlank(definition.getDisplayName())) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Presentation definition display name is required.");
        }
        List<Credential> requestedCredentials = definition.getCredentials();
        if (requestedCredentials != null && !requestedCredentials.isEmpty()) {
            validateCredentialIds(requestedCredentials);
        }
    }

    /**
     * Validates that every credential in the given list has a non-blank ID that contains only
     * alphanumeric characters, underscores, or hyphens.
     *
     * @param requestedCredentials the list of requested credentials to validate
     * @throws PresentationManagementClientException if any credential ID is blank or contains
     * invalid characters
     */
    private void validateCredentialIds(List<Credential> requestedCredentials)
            throws PresentationManagementClientException {

        for (Credential credential : requestedCredentials) {
            if (credential == null) {
                continue;
            }
            String credentialId = credential.getIdentifier();
            if (StringUtils.isBlank(credentialId)) {
                throw new PresentationManagementClientException(
                        PresentationManagementErrorCode.VALIDATION_ERROR,
                        "A credential ID is required for each requested credential. "
                                + "Use alphanumeric characters, underscores, or hyphens only.");
            }
            if (!credentialId.matches(Constants.CREDENTIAL_ID_PATTERN)) {
                throw new PresentationManagementClientException(
                        PresentationManagementErrorCode.VALIDATION_ERROR,
                        "Credential ID '" + credentialId + "' is invalid. "
                                + "Only alphanumeric characters, underscores, and hyphens are allowed.");
            }
        }
    }
}
