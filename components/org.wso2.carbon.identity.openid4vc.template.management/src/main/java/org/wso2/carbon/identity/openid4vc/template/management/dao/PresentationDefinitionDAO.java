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

package org.wso2.carbon.identity.openid4vc.template.management.dao;

import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.ConnectedIdpInfo;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.util.List;

/**
 * Data access object interface for presentation definition operations.
 */
public interface PresentationDefinitionDAO {

    /**
     * Creates a new presentation definition in the database.
     *
     * @param presentationDefinition the presentation definition to create
     * @throws PresentationManagementException if a database error occurs or a definition with the same name
     *                                         already exists
     */
    void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws PresentationManagementException;

    /**
     * Looks up a presentation definition by its unique identifier.
     *
     * @param definitionId the unique identifier of the presentation definition
     * @param tenantId     the tenant ID scoping the lookup
     * @return the matching {@link PresentationDefinition}, or {@code null} if not found
     * @throws PresentationManagementException if a database error occurs
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
     * Deletes a presentation definition and its associated credentials.
     *
     * @param definitionId the unique identifier of the presentation definition to delete
     * @param tenantId     the tenant ID scoping the delete
     * @throws PresentationManagementException if a database error occurs
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
     * Looks up a presentation definition by its unique identifier within the given tenant.
     *
     * @param identifier the user-facing unique identifier of the presentation definition
     * @param tenantId   the tenant ID scoping the lookup
     * @return the matching {@link PresentationDefinition}, or {@code null} if not found
     * @throws PresentationManagementException if a database error occurs
     */
    PresentationDefinition getPresentationDefinitionByIdentifier(String identifier, int tenantId)
            throws PresentationManagementException;

    /**
     * Checks whether a presentation definition with the given identifier exists for the tenant.
     *
     * @param identifier the user-facing unique identifier of the presentation definition
     * @param tenantId   the tenant ID scoping the lookup
     * @return {@code true} if a definition with that identifier exists, {@code false} otherwise
     * @throws PresentationManagementException if a database error occurs
     */
    boolean presentationDefinitionIdentifierExists(String identifier, int tenantId)
            throws PresentationManagementException;

    /**
     * Returns a cursor-paginated, filtered page of presentation definitions for the given tenant.
     * The result contains summary fields only (no credential detail).
     *
     * @param limit           the maximum number of rows to return, including the extra probe row
     *                        used to detect whether a next/previous page exists
     * @param tenantId        the tenant ID scoping the query
     * @param sortOrder       the cursor sort direction — either {@code "ASC"} or {@code "DESC"}
     * @param expressionNodes the parsed filter and cursor expression nodes
     * @return an ordered list of matching presentation definitions
     * @throws PresentationManagementException if the query fails
     */
    List<PresentationDefinition> list(Integer limit, Integer tenantId, String sortOrder,
            List<ExpressionNode> expressionNodes) throws PresentationManagementException;

    /**
     * Checks whether any federated authenticator connection references the given presentation definition.
     *
     * @param definitionId the unique identifier of the presentation definition
     * @param tenantId     the tenant ID scoping the check
     * @return {@code true} if at least one connection references this definition, {@code false} otherwise
     * @throws PresentationManagementException if a database error occurs
     */
    boolean isDefinitionInUse(String definitionId, int tenantId) throws PresentationManagementException;

    /**
     * Returns all federated authenticator connections that reference the given presentation definition.
     *
     * @param definitionId the unique identifier of the presentation definition
     * @param tenantId     the tenant ID scoping the query
     * @return a list of {@link ConnectedIdpInfo} objects containing the IDP UUID and display name
     * @throws PresentationManagementException if a database error occurs
     */
    List<ConnectedIdpInfo> getConnectedIdps(String definitionId, int tenantId)
            throws PresentationManagementException;

    /**
     * Removes stale IDP claim mappings for claim paths that were deleted or renamed in the given
     * presentation definition. Cleans up {@code IDP_CLAIM} rows across all connections that reference
     * this definition so that obsolete attribute mappings do not persist after a definition update.
     *
     * @param definitionId    the unique identifier of the presentation definition that was updated
     * @param staleClaimPaths the claim paths that no longer exist in the updated definition
     *                        (dot-joined, e.g. {@code "given_name"})
     * @param tenantId        the tenant ID scoping the delete
     * @throws PresentationManagementException if a database error occurs
     */
    void removeStaleIdpClaimMappings(String definitionId, List<String> staleClaimPaths, int tenantId)
            throws PresentationManagementException;

    /**
     * Updates the presentation definition and removes stale IDP claim mappings in a single transaction,
     * so the two writes succeed or fail together.
     *
     * @param presentationDefinition the updated presentation definition
     * @param staleClaimPaths        claim paths that no longer exist in the updated definition and whose
     *                               {@code IDP_CLAIM} rows must be deleted; may be empty
     * @param tenantId               the tenant ID scoping the write
     * @throws PresentationManagementException if a database error occurs
     */
    void updatePresentationDefinition(PresentationDefinition presentationDefinition,
            List<String> staleClaimPaths, int tenantId) throws PresentationManagementException;

    /**
     * Counts the presentation definitions matching the given filter for the tenant,
     * excluding any cursor expression nodes.
     *
     * @param tenantId        the tenant ID scoping the count
     * @param expressionNodes the parsed filter expression nodes (cursor nodes are excluded before counting)
     * @return the total number of matching definitions
     * @throws PresentationManagementException if a database error occurs
     */
    Integer getDefinitionsCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws PresentationManagementException;
}
