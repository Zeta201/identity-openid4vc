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

package org.wso2.carbon.identity.openid4vc.template.management.service;

import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.ConnectedIdpInfo;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinitionSearchResult;

import java.util.List;

/**
 * Service interface for managing presentation definitions.
 * Presentation definitions specify what credentials are required for a verifier's use case.
 */
public interface PresentationDefinitionService {

    /**
     * Creates a new presentation definition for the given tenant.
     *
     * @param presentationDefinition the presentation definition to create
     * @param tenantId               the tenant ID scoping the creation
     * @return the created presentation definition, with its generated ID populated
     * @throws PresentationManagementException if validation fails, the definition already exists,
     * or a database error occurs
     */
    PresentationDefinition createPresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId)
            throws PresentationManagementException;

    /**
     * Returns the presentation definition with the given ID for the specified tenant.
     *
     * @param definitionId the unique identifier of the presentation definition
     * @param tenantId     the tenant ID scoping the lookup
     * @return the matching presentation definition
     * @throws PresentationManagementException if the definition is not found or a database error occurs
     */
    PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationManagementException;

    /**
     * Returns all presentation definitions stored for the given tenant.
     *
     * @param tenantId the tenant ID whose definitions should be retrieved
     * @return all presentation definitions for the tenant, or an empty list if none exist
     * @throws PresentationManagementException if a database error occurs
     */
    List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws PresentationManagementException;

    /**
     * Updates the name, description, and credential list of an existing presentation definition.
     *
     * @param presentationDefinition the updated presentation definition
     * @param tenantId               the tenant ID scoping the update
     * @return the updated presentation definition
     * @throws PresentationManagementException if the definition is not found or a database error occurs
     */
    PresentationDefinition updatePresentationDefinition(
            PresentationDefinition presentationDefinition, int tenantId)
            throws PresentationManagementException;

    /**
     * Deletes the presentation definition with the given ID, provided it is not referenced
     * by any federated authenticator connection.
     *
     * @param definitionId the unique identifier of the presentation definition to delete
     * @param tenantId     the tenant ID scoping the delete
     * @throws PresentationManagementException if the definition is not found, is in use by a connection,
     * or a database error occurs
     */
    void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationManagementException;

    /**
     * Checks whether a presentation definition with the given ID exists for the tenant.
     *
     * @param definitionId the unique identifier of the presentation definition
     * @param tenantId     the tenant ID scoping the lookup
     * @return {@code true} if the definition exists, {@code false} otherwise
     * @throws PresentationManagementException if a database error occurs
     */
    boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws PresentationManagementException;

    /**
     * Looks up a presentation definition by its unique user-facing identifier within the given tenant.
     *
     * @param identifier the unique identifier of the presentation definition
     * @param tenantId   the tenant ID scoping the lookup
     * @return the matching presentation definition, or {@code null} if not found
     * @throws PresentationManagementException if a database error occurs
     */
    PresentationDefinition getPresentationDefinitionByIdentifier(String identifier, int tenantId)
            throws PresentationManagementException;

    /**
     * Returns a cursor-paginated, filtered page of presentation definitions for the given tenant.
     *
     * @param after      the base64-encoded lower-bound cursor for forward pagination; may be {@code null}
     * @param before     the base64-encoded upper-bound cursor for backward pagination; may be {@code null}
     * @param limit      the maximum number of rows to return, including the extra probe row used to detect
     *                   whether a next or previous page exists
     * @param filter     the SCIM-style filter expression; may be {@code null}
     * @param sortOrder  the sort direction — either {@code "ASC"} or {@code "DESC"}
     * @param tenantId   the tenant ID scoping the query
     * @return a search result containing the total matching count and the current page of definitions
     * @throws PresentationManagementException if the query fails
     */
    PresentationDefinitionSearchResult listWithPagination(String after, String before, Integer limit,
            String filter, String sortOrder, int tenantId) throws PresentationManagementException;

    /**
     * Returns all federated authenticator connections that reference the given presentation definition.
     *
     * @param definitionId the unique identifier of the presentation definition
     * @param tenantId     the tenant ID scoping the query
     * @return a list of {@link ConnectedIdpInfo} objects containing each IDP's UUID and display name
     * @throws PresentationManagementException if a database error occurs
     */
    List<ConnectedIdpInfo> getConnectedIdps(String definitionId, int tenantId)
            throws PresentationManagementException;

    /**
     * Replaces all issuer configurations for a specific credential within a presentation definition.
     * The replacement is atomic: existing configs are deleted and the new list is inserted in one
     * transaction. At least one {@link PresentationDefinition.IssuerConfig} must be provided.
     *
     * @param definitionId         the UUID of the parent presentation definition
     * @param credentialIdentifier the user-facing identifier of the target credential
     * @param issuerConfigs        the replacement list of issuer configurations; must not be empty
     * @param tenantId             the tenant ID scoping the update
     * @throws PresentationManagementException if the definition or credential is not found,
     *                                         issuerConfigs is empty, or a database error occurs
     */
    void replaceIssuerConfigs(String definitionId, String credentialIdentifier,
            List<PresentationDefinition.IssuerConfig> issuerConfigs, int tenantId)
            throws PresentationManagementException;

}
