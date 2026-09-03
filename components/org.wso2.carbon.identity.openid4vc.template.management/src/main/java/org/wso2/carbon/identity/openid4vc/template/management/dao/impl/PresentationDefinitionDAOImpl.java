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


import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionSQLConstants;
import org.wso2.carbon.identity.openid4vc.template.management.constant.SQLConstants;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementErrorCode;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementServerException;
import org.wso2.carbon.identity.openid4vc.template.management.model.ConnectedIdpInfo;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.ClaimConstraint;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.IssuerConfig;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.template.management.util.Constants;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterQueryBuilder;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterUtil;


import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementation of {@link PresentationDefinitionDAO} using JDBC.
 * Uses two tables: {@code IDN_PRESENTATION_DEFINITION} (parent) and
 * {@code IDN_PD_CREDENTIAL} (child).
 */
public class PresentationDefinitionDAOImpl implements PresentationDefinitionDAO {


    @Override
    public void createPresentationDefinition(PresentationDefinition presentationDefinition)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.INSERT_DEFINITION)) {
                    ps.setString(1, presentationDefinition.getDefinitionId());
                    ps.setString(2, presentationDefinition.getIdentifier());
                    ps.setString(3, presentationDefinition.getDisplayName());
                    ps.setString(4, presentationDefinition.getDescription());
                    ps.setInt(5, presentationDefinition.getTenantId());
                    ps.executeUpdate();
                }
                insertCredentials(connection, presentationDefinition.getDefinitionId(),
                        presentationDefinition.getRequestedCredentials(), presentationDefinition.getTenantId());
                IdentityDatabaseUtil.commitTransaction(connection);

            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                if (e.getSQLState() != null &&
                        e.getSQLState().startsWith(Constants.SQL_STATE_CONSTRAINT_VIOLATION_PREFIX)) {
                    throw new PresentationManagementClientException(
                            PresentationManagementErrorCode.DEFINITION_ALREADY_EXISTS,
                            "Presentation definition with identifier '" +
                                    presentationDefinition.getIdentifier() + "' already exists.", e);
                }
                throw new PresentationManagementServerException(
                        PresentationManagementErrorCode.DATABASE_ERROR,
                        "Error creating presentation definition: " +
                                presentationDefinition.getDefinitionId(), e);
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error obtaining DB connection for createPresentationDefinition.", e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            PresentationDefinition definition;
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.SELECT_DEFINITION_BY_ID)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    definition = buildSingleDefinition(rs);
                }
            }
            if (definition != null) {
                loadIssuerConfigsForDefinition(connection, definition);
            }
            return definition;
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error retrieving presentation definition: " + definitionId, e);
        }
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            List<PresentationDefinition> definitions;
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.SELECT_ALL_DEFINITIONS)) {
                ps.setInt(1, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    definitions = buildDefinitionList(rs);
                }
            }
            for (PresentationDefinition definition : definitions) {
                loadIssuerConfigsForDefinition(connection, definition);
            }
            return definitions;
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error retrieving all presentation definitions.", e);
        }
    }

    @Override
    public void updatePresentationDefinition(PresentationDefinition presentationDefinition,
            List<String> staleClaimPaths, int tenantId) throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.UPDATE_DEFINITION)) {
                    ps.setString(1, presentationDefinition.getDisplayName());
                    ps.setString(2, presentationDefinition.getDescription());
                    ps.setString(3, presentationDefinition.getDefinitionId());
                    ps.setInt(4, presentationDefinition.getTenantId());
                    ps.executeUpdate();
                }
                upsertCredentials(connection, presentationDefinition.getDefinitionId(),
                        presentationDefinition.getRequestedCredentials(), tenantId);
                if (staleClaimPaths != null && !staleClaimPaths.isEmpty()) {
                    String placeholders = String.join(",",
                            Collections.nCopies(staleClaimPaths.size(), "?"));
                    String sql = PresentationDefinitionSQLConstants.DELETE_STALE_IDP_CLAIMS_PREFIX + placeholders
                            + PresentationDefinitionSQLConstants.DELETE_STALE_IDP_CLAIMS_SUFFIX;
                    try (PreparedStatement ps = connection.prepareStatement(sql)) {
                        int i = 1;
                        ps.setInt(i++, tenantId);
                        for (String path : staleClaimPaths) {
                            ps.setString(i++, path);
                        }
                        ps.setString(i++, presentationDefinition.getDefinitionId());
                        ps.setInt(i, tenantId);
                        ps.executeUpdate();
                    }
                }
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error updating presentation definition with cleanup: " +
                            presentationDefinition.getDefinitionId(), e);
        }
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.DELETE_DEFINITION)) {
                    ps.setString(1, definitionId);
                    ps.setInt(2, tenantId);
                    ps.executeUpdate();
                }
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error deleting presentation definition: " + definitionId, e);
        }
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.EXISTS_DEFINITION)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error checking presentation definition existence: " + definitionId, e);
        }
    }

    @Override
    public List<PresentationDefinition> list(Integer limit, Integer tenantId, String sortOrder,
            List<ExpressionNode> expressionNodes) throws PresentationManagementException {

        List<PresentationDefinition> results = new ArrayList<>();
        try {
            PresentationDefinitionFilterQueryBuilder filterQueryBuilder =
                    PresentationDefinitionFilterUtil.getFilterQueryBuilder(expressionNodes);
            Map<Integer, String> filterAttributeValue = filterQueryBuilder.getFilterAttributeValue();

            try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
                String databaseName = connection.getMetaData().getDatabaseProductName();
                String sqlStmt = buildListSql(databaseName, tenantId, filterQueryBuilder.getFilterQuery(),
                        sortOrder, limit);

                try (PreparedStatement ps = connection.prepareStatement(sqlStmt)) {
                    if (filterAttributeValue != null) {
                        for (Map.Entry<Integer, String> entry : filterAttributeValue.entrySet()) {
                            ps.setString(entry.getKey(), entry.getValue());
                        }
                    }
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            PresentationDefinition definition = new PresentationDefinition.Builder()
                                    .definitionId(rs.getString(Constants.COL_DEFINITION_ID))
                                    .identifier(rs.getString(Constants.COL_IDENTIFIER))
                                    .displayName(rs.getString(Constants.COL_DISPLAY_NAME))
                                    .description(rs.getString(Constants.COL_DESCRIPTION))
                                    .tenantId(tenantId)
                                    .build();
                            definition.setCursorKey(rs.getInt(Constants.COL_CURSOR_KEY));
                            results.add(definition);
                        }
                    }
                }
            }
        } catch (PresentationManagementClientException e) {
            throw e;
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error listing presentation definitions with pagination.", e);
        }
        return results;
    }

    @Override
    public Integer getDefinitionsCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws PresentationManagementException {

        try {
            List<ExpressionNode> expressionNodesCopy = new ArrayList<>(expressionNodes);
            expressionNodesCopy.removeIf(expressionNode ->
                    Constants.AFTER.equals(expressionNode.getAttributeValue()) ||
                    Constants.BEFORE.equals(expressionNode.getAttributeValue()));

            PresentationDefinitionFilterQueryBuilder filterQueryBuilder =
                    PresentationDefinitionFilterUtil.getFilterQueryBuilder(expressionNodesCopy);
            Map<Integer, String> filterAttributeValue = filterQueryBuilder.getFilterAttributeValue();

            String sqlStmt = Constants.GET_PD_COUNT
                    + filterQueryBuilder.getFilterQuery()
                    + Constants.GET_PD_COUNT_TAIL;

            try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                 PreparedStatement ps = connection.prepareStatement(sqlStmt)) {

                if (filterAttributeValue != null) {
                    for (Map.Entry<Integer, String> entry : filterAttributeValue.entrySet()) {
                        ps.setString(entry.getKey(), entry.getValue());
                    }
                }
                ps.setInt((filterAttributeValue != null ? filterAttributeValue.size() : 0) + 1, tenantId);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }
            }
        } catch (PresentationManagementClientException e) {
            throw e;
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error counting presentation definitions.", e);
        }
        return 0;
    }

    @Override
    public boolean isDefinitionInUse(String definitionId, int tenantId)
            throws PresentationManagementException {

        String countSql = PresentationDefinitionSQLConstants.COUNT_CONNECTIONS_USING_DEFINITION;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(countSql)) {
            ps.setString(1, definitionId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error checking whether presentation definition is in use: " + definitionId, e);
        }
    }

    @Override
    public List<ConnectedIdpInfo> getConnectedIdps(String definitionId, int tenantId)
            throws PresentationManagementException {

        List<ConnectedIdpInfo> idps = new ArrayList<>();
        String connsSql = PresentationDefinitionSQLConstants.GET_CONNECTED_CONNECTIONS;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(connsSql)) {
            ps.setString(1, definitionId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    idps.add(new ConnectedIdpInfo(
                            rs.getString(Constants.COL_CONNECTION_ID),
                            rs.getString(Constants.COL_CONNECTION_NAME)));
                }
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error fetching connections using presentation definition: " + definitionId, e);
        }
        return idps;
    }

    @Override
    public void removeStaleIdpClaimMappings(String definitionId, List<String> staleClaimPaths, int tenantId)
            throws PresentationManagementException {

        if (staleClaimPaths == null || staleClaimPaths.isEmpty()) {
            return;
        }
        String placeholders = String.join(",", Collections.nCopies(staleClaimPaths.size(), "?"));
        String sql = PresentationDefinitionSQLConstants.DELETE_STALE_IDP_CLAIMS_PREFIX + placeholders
                + PresentationDefinitionSQLConstants.DELETE_STALE_IDP_CLAIMS_SUFFIX;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                int paramIndex = 1;
                ps.setInt(paramIndex++, tenantId);
                for (String claimPath : staleClaimPaths) {
                    ps.setString(paramIndex++, claimPath);
                }
                ps.setString(paramIndex++, definitionId);
                ps.setInt(paramIndex, tenantId);
                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error removing stale IDP claim mappings for presentation definition: " + definitionId, e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByIdentifier(String identifier, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            PresentationDefinition definition;
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.SELECT_DEFINITION_BY_IDENTIFIER)) {
                ps.setString(1, identifier);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    definition = buildSingleDefinition(rs);
                }
            }
            if (definition != null) {
                loadIssuerConfigsForDefinition(connection, definition);
            }
            return definition;
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error retrieving presentation definition by identifier: " + identifier, e);
        }
    }

    @Override
    public boolean presentationDefinitionIdentifierExists(String identifier, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.EXISTS_DEFINITION_BY_IDENTIFIER)) {
                ps.setString(1, identifier);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error checking presentation definition identifier existence: " + identifier, e);
        }
    }

    /**
     * Builds the paginated list SQL statement for the given database type, applying
     * the appropriate dialect-specific syntax for MSSQL, Oracle, and standard databases.
     *
     * @param databaseName the database product name used to detect dialect
     * @param tenantId     the tenant whose definitions are being listed
     * @param filterQuery  the WHERE clause fragment produced by the filter query builder
     * @param sortOrder    the sort direction, either {@code ASC} or {@code DESC}
     * @param limit        the maximum number of rows to return
     * @return the complete SQL SELECT statement with limit and sort applied
     */
    private String buildListSql(String databaseName, Integer tenantId, String filterQuery,
            String sortOrder, Integer limit) {

        // Map to a literal to prevent any SQL injection via the sort direction.
        String safeSortOrder = Constants.DESC_SORT_ORDER.equalsIgnoreCase(sortOrder)
                ? Constants.DESC_SORT_ORDER : Constants.ASC_SORT_ORDER;
        if (databaseName.contains(SQLConstants.MICROSOFT)) {
            return String.format(Constants.GET_PD_LIST_MSSQL, limit)
                    + filterQuery
                    + String.format(Constants.GET_PD_LIST_TAIL_MSSQL, tenantId, safeSortOrder);
        } else if (databaseName.contains(SQLConstants.ORACLE)) {
            return Constants.GET_PD_LIST + filterQuery
                    + String.format(Constants.GET_PD_LIST_TAIL_ORACLE,
                        tenantId, safeSortOrder, limit);
        }
        return Constants.GET_PD_LIST + filterQuery
                + String.format(Constants.GET_PD_LIST_TAIL, tenantId, safeSortOrder, limit);
    }

    /**
     * Upserts each credential using its integer PK for UPDATE and DELETE operations.
     * Loads the existing identifier-to-ID map first, then for each credential in the
     * new list either updates the existing row by ID or inserts a new one.
     * Claims are replaced per credential. Removed credentials are deleted by ID.
     */
    private void upsertCredentials(Connection connection, String definitionId,
            List<RequestedCredential> credentials, int tenantId) throws SQLException {

        if (credentials == null || credentials.isEmpty()) {
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.DELETE_CREDENTIALS)) {
                ps.setString(1, definitionId);
                ps.executeUpdate();
            }
            return;
        }

        Map<String, Integer> existingIds = loadCredentialIds(connection, definitionId);
        List<Integer> keptIds = new ArrayList<>();

        for (RequestedCredential cred : credentials) {
            Integer existingId = existingIds.get(cred.getIdentifier());
            int credentialDbId;

            if (existingId != null) {
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.UPDATE_CREDENTIAL)) {
                    ps.setString(1, cred.getType());
                    ps.setString(2, cred.getFormat());
                    ps.setInt(3, existingId);
                    ps.executeUpdate();
                }
                credentialDbId = existingId;
            } else {
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.INSERT_CREDENTIAL,
                        Statement.RETURN_GENERATED_KEYS)) {
                    ps.setString(1, definitionId);
                    ps.setString(2, cred.getIdentifier());
                    ps.setString(3, cred.getType());
                    ps.setString(4, cred.getFormat());
                    ps.setInt(5, tenantId);
                    ps.executeUpdate();
                    try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                        if (!generatedKeys.next()) {
                            throw new SQLException("Inserting credential returned no generated key.");
                        }
                        credentialDbId = generatedKeys.getInt(1);
                    }
                }
                insertIssuerConfigs(connection, credentialDbId, cred.getIssuerConfigs(), tenantId);
            }
            keptIds.add(credentialDbId);
            replaceClaimsForCredential(connection, credentialDbId, cred.getClaims(), tenantId);
        }

        deleteRemovedCredentials(connection, definitionId, keptIds);
    }

    @Override
    public void replaceIssuerConfigs(String definitionId, String credentialIdentifier,
            List<PresentationDefinition.IssuerConfig> issuerConfigs, int tenantId)
            throws PresentationManagementException {

        if (issuerConfigs == null || issuerConfigs.isEmpty()) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.VALIDATION_ERROR,
                    "At least one issuer configuration is required for credential '" + credentialIdentifier + "'.");
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            Map<String, Integer> existingIds = loadCredentialIds(connection, definitionId);
            Integer credentialDbId = existingIds.get(credentialIdentifier);
            if (credentialDbId == null) {
                throw new PresentationManagementClientException(
                        PresentationManagementErrorCode.VALIDATION_ERROR,
                        "Credential '" + credentialIdentifier + "' not found in definition '" + definitionId + "'.");
            }
            try {
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.DELETE_ISSUER_CONFIGS_FOR_CREDENTIAL)) {
                    ps.setInt(1, credentialDbId);
                    ps.executeUpdate();
                }
                insertIssuerConfigs(connection, credentialDbId, issuerConfigs, tenantId);
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (PresentationManagementClientException e) {
            throw e;
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error replacing issuer configs for credential '" + credentialIdentifier + "'.", e);
        }
    }

    private Map<String, Integer> loadCredentialIds(Connection connection,
            String definitionId) throws SQLException {

        Map<String, Integer> idMap = new LinkedHashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(
                PresentationDefinitionSQLConstants.SELECT_CREDENTIAL_IDS)) {
            ps.setString(1, definitionId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    idMap.put(rs.getString(Constants.COL_IDENTIFIER), rs.getInt(Constants.COL_DEFINITION_ID));
                }
            }
        }
        return idMap;
    }

    private void replaceClaimsForCredential(Connection connection, int credentialDbId,
            List<ClaimConstraint> claims, int tenantId) throws SQLException {

        try (PreparedStatement ps = connection.prepareStatement(
                PresentationDefinitionSQLConstants.DELETE_CLAIMS_FOR_CREDENTIAL)) {
            ps.setInt(1, credentialDbId);
            ps.executeUpdate();
        }
        insertClaims(connection, credentialDbId, claims, tenantId);
    }

    private void deleteRemovedCredentials(Connection connection, String definitionId,
            List<Integer> keptIds) throws SQLException {

        String placeholders = String.join(",", Collections.nCopies(keptIds.size(), "?"));
        String sql = PresentationDefinitionSQLConstants.DELETE_REMOVED_CREDENTIALS_PREFIX
                + placeholders + ")";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, definitionId);
            for (int i = 0; i < keptIds.size(); i++) {
                ps.setInt(i + 2, keptIds.get(i));
            }
            ps.executeUpdate();
        }
    }

    /**
     * Inserts the given list of requested credentials into {@code IDN_PD_CREDENTIAL}
     * and their claim constraints into {@code IDN_PD_CLAIM}, under the supplied definition ID.
     * Each credential is inserted individually so the auto-generated {@code ID} can be
     * retrieved and passed as the FK for its claim rows.
     *
     * @param connection   the active database connection with an open transaction
     * @param definitionId the ID of the parent presentation definition
     * @param credentials  the list of requested credentials to persist; no-op when null or empty
     * @throws SQLException if any JDBC operation fails
     */
    private void insertCredentials(Connection connection, String definitionId,
            List<RequestedCredential> credentials, int tenantId) throws SQLException {

        if (credentials == null || credentials.isEmpty()) {
            return;
        }
        for (RequestedCredential cred : credentials) {
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.INSERT_CREDENTIAL, Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, definitionId);
                ps.setString(2, cred.getIdentifier());
                ps.setString(3, cred.getType());
                ps.setString(4, cred.getFormat());
                ps.setInt(5, tenantId);
                ps.executeUpdate();
                int credentialDbId;
                try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                    if (!generatedKeys.next()) {
                        throw new SQLException("Inserting credential returned no generated key.");
                    }
                    credentialDbId = generatedKeys.getInt(1);
                }
                insertClaims(connection, credentialDbId, cred.getClaims(), tenantId);
                insertIssuerConfigs(connection, credentialDbId, cred.getIssuerConfigs(), tenantId);
            }
        }
    }

    private void insertIssuerConfigs(Connection connection, int credentialDbId,
            List<IssuerConfig> issuerConfigs, int tenantId) throws SQLException {

        if (issuerConfigs == null || issuerConfigs.isEmpty()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(
                PresentationDefinitionSQLConstants.INSERT_ISSUER_CONFIG)) {
            for (IssuerConfig config : issuerConfigs) {
                ps.setInt(1, credentialDbId);
                ps.setString(2, config.getKeySourceType());
                ps.setString(3, config.getIssuerUrl());
                ps.setString(4, config.getKeySource());
                ps.setInt(5, tenantId);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    private List<IssuerConfig> loadIssuerConfigs(Connection connection,
            int credentialDbId) throws SQLException {

        List<IssuerConfig> configs = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(
                PresentationDefinitionSQLConstants.SELECT_ISSUER_CONFIGS)) {
            ps.setInt(1, credentialDbId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    IssuerConfig config = new IssuerConfig();
                    config.setKeySourceType(rs.getString(Constants.COL_KEY_SOURCE_TYPE));
                    config.setIssuerUrl(rs.getString(Constants.COL_ISSUER_URL));
                    config.setKeySource(rs.getString(Constants.COL_KEY_SOURCE));
                    configs.add(config);
                }
            }
        }
        return configs;
    }

    private void loadIssuerConfigsForDefinition(Connection connection,
            PresentationDefinition definition) throws SQLException {

        if (definition.getRequestedCredentials() == null) {
            return;
        }
        Map<String, Integer> credentialIds = loadCredentialIds(connection, definition.getDefinitionId());
        for (RequestedCredential cred : definition.getRequestedCredentials()) {
            Integer credentialDbId = credentialIds.get(cred.getIdentifier());
            if (credentialDbId != null) {
                cred.setIssuerConfigs(loadIssuerConfigs(connection, credentialDbId));
            }
        }
    }

    /**
     * Inserts the claim constraints for a single credential into {@code IDN_PD_CLAIM},
     * using a JDBC batch execute. No-op when {@code claims} is null or empty.
     *
     * @param connection    the active database connection with an open transaction
     * @param credentialDbId the auto-generated PK of the parent {@code IDN_PD_CREDENTIAL} row
     * @param claims        the claim constraints to persist
     * @throws SQLException if any JDBC operation fails
     */
    private void insertClaims(Connection connection, int credentialDbId,
            List<ClaimConstraint> claims, int tenantId) throws SQLException {

        if (claims == null || claims.isEmpty()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(PresentationDefinitionSQLConstants.INSERT_CLAIM)) {
            for (ClaimConstraint claim : claims) {
                ps.setInt(1, credentialDbId);
                ps.setString(2, claim.getPath() != null ? claim.getPath() : "");
                ps.setBoolean(3, claim.isMandatory());
                ps.setInt(4, tenantId);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    /**
     * Reads a single {@link PresentationDefinition} with its credentials and claim constraints
     * from the given result set. Each row represents a (credential, claim) pair due to the
     * double LEFT JOIN; rows are grouped by credential ID and claims are accumulated per credential.
     *
     * @param rs the result set positioned before the first row
     * @return the assembled {@link PresentationDefinition}, or {@code null} if the result set is empty
     * @throws SQLException if reading any column from the result set fails
     */
    private PresentationDefinition buildSingleDefinition(ResultSet rs) throws SQLException {

        String definitionId = null;
        String identifier = null;
        String displayName = null;
        String description = null;
        int tenantId = 0;
        Map<String, RequestedCredential> credMap = new LinkedHashMap<>();
        Map<String, List<ClaimConstraint>> claimsMap = new LinkedHashMap<>();

        while (rs.next()) {
            if (definitionId == null) {
                definitionId = rs.getString(Constants.COL_DEFINITION_ID);
                identifier = rs.getString(Constants.COL_IDENTIFIER);
                displayName = rs.getString(Constants.COL_DISPLAY_NAME);
                description = rs.getString(Constants.COL_DESCRIPTION);
                tenantId = rs.getInt(Constants.COL_TENANT_ID);
            }
            String credentialId = rs.getString(Constants.COL_CREDENTIAL_ID);
            if (credentialId != null) {
                if (!credMap.containsKey(credentialId)) {
                    credMap.put(credentialId, mapCredentialRow(rs));
                    claimsMap.put(credentialId, new ArrayList<>());
                }
                if (rs.getString(Constants.COL_CLAIM_PATH) != null) {
                    claimsMap.get(credentialId).add(mapClaimRow(rs));
                }
            }
        }

        if (definitionId == null) {
            return null;
        }
        for (Map.Entry<String, RequestedCredential> entry : credMap.entrySet()) {
            entry.getValue().setClaims(claimsMap.get(entry.getKey()));
        }
        return new PresentationDefinition.Builder()
                .definitionId(definitionId)
                .identifier(identifier)
                .displayName(displayName)
                .description(description)
                .tenantId(tenantId)
                .requestedCredentials(new ArrayList<>(credMap.values()))
                .build();
    }

    /**
     * Reads all {@link PresentationDefinition} instances with their credentials and claim
     * constraints from the given result set. Each row represents a (credential, claim) pair;
     * rows are grouped first by definition ID, then by credential ID, accumulating claims
     * per credential.
     *
     * @param rs the result set positioned before the first row
     * @return an ordered list of assembled {@link PresentationDefinition} instances
     * @throws SQLException if reading any column from the result set fails
     */
    private List<PresentationDefinition> buildDefinitionList(ResultSet rs) throws SQLException {

        Map<String, PresentationDefinition.Builder> builders = new LinkedHashMap<>();
        Map<String, Map<String, RequestedCredential>> credsByDef = new LinkedHashMap<>();
        Map<String, List<ClaimConstraint>> claimsByCredential = new LinkedHashMap<>();

        while (rs.next()) {
            String definitionId = rs.getString(Constants.COL_DEFINITION_ID);
            if (!builders.containsKey(definitionId)) {
                builders.put(definitionId, new PresentationDefinition.Builder()
                        .definitionId(definitionId)
                        .identifier(rs.getString(Constants.COL_IDENTIFIER))
                        .displayName(rs.getString(Constants.COL_DISPLAY_NAME))
                        .description(rs.getString(Constants.COL_DESCRIPTION))
                        .tenantId(rs.getInt(Constants.COL_TENANT_ID)));
                credsByDef.put(definitionId, new LinkedHashMap<>());
            }
            String credentialId = rs.getString(Constants.COL_CREDENTIAL_ID);
            if (credentialId != null) {
                String compositeKey = definitionId + "|" + credentialId;
                if (!credsByDef.get(definitionId).containsKey(credentialId)) {
                    credsByDef.get(definitionId).put(credentialId, mapCredentialRow(rs));
                    claimsByCredential.put(compositeKey, new ArrayList<>());
                }
                if (rs.getString(Constants.COL_CLAIM_PATH) != null) {
                    claimsByCredential.get(compositeKey).add(mapClaimRow(rs));
                }
            }
        }

        List<PresentationDefinition> result = new ArrayList<>();
        for (Map.Entry<String, PresentationDefinition.Builder> builderEntry : builders.entrySet()) {
            String definitionId = builderEntry.getKey();
            Map<String, RequestedCredential> creds = credsByDef.get(definitionId);
            for (Map.Entry<String, RequestedCredential> credEntry : creds.entrySet()) {
                credEntry.getValue().setClaims(claimsByCredential.get(definitionId + "|" + credEntry.getKey()));
            }
            result.add(builderEntry.getValue()
                    .requestedCredentials(new ArrayList<>(creds.values()))
                    .build());
        }
        return result;
    }

    /**
     * Maps the credential columns of the current result set row to a {@link RequestedCredential}.
     * Claims are NOT read here; they are accumulated separately and set by the caller after grouping.
     *
     * @param rs the result set positioned at the row to map
     * @return a {@link RequestedCredential} populated from the current row, with an empty claims list
     * @throws SQLException if reading any column from the result set fails
     */
    private RequestedCredential mapCredentialRow(ResultSet rs) throws SQLException {

        RequestedCredential cred = new RequestedCredential();
        cred.setIdentifier(rs.getString(Constants.COL_CREDENTIAL_ID));
        cred.setType(rs.getString(Constants.COL_CREDENTIAL_TYPE));
        cred.setFormat(rs.getString(Constants.COL_CREDENTIAL_FORMAT));
        return cred;
    }

    /**
     * Maps the claim columns of the current result set row to a {@link ClaimConstraint}.
     *
     * @param rs the result set positioned at the row to map
     * @return a {@link ClaimConstraint} populated from the current row
     * @throws SQLException if reading any column from the result set fails
     */
    private ClaimConstraint mapClaimRow(ResultSet rs) throws SQLException {

        ClaimConstraint claim = new ClaimConstraint();
        claim.setPath(rs.getString(Constants.COL_CLAIM_PATH));
        claim.setMandatory(rs.getBoolean(Constants.COL_IS_MANDATORY));
        return claim;
    }

}
