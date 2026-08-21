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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionSQLConstants;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementErrorCode;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementServerException;
import org.wso2.carbon.identity.openid4vc.template.management.model.ConnectedConnectionInfo;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.ClaimConstraint;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.template.management.util.Constants;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterQueryBuilder;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterUtil;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Implementation of {@link PresentationDefinitionDAO} using JDBC.
 * Uses two tables: {@code IDN_PRESENTATION_DEFINITION} (parent) and
 * {@code IDN_PD_CREDENTIAL} (child).
 */
public class PresentationDefinitionDAOImpl implements PresentationDefinitionDAO {

    private static final Gson GSON = new Gson();
    private static final Type CLAIM_CONSTRAINT_LIST_TYPE =
            new TypeToken<List<ClaimConstraint>>() { }.getType();
    private static final Pattern PEM_PATTERN = Pattern.compile(
            "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");


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
                        presentationDefinition.getRequestedCredentials());
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
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.SELECT_DEFINITION_BY_ID)) {
                ps.setString(1, definitionId);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    return buildSingleDefinition(rs);
                }
            }
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
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.SELECT_ALL_DEFINITIONS)) {
                ps.setInt(1, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    return buildDefinitionList(rs);
                }
            }
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
                try (PreparedStatement ps = connection.prepareStatement(
                        PresentationDefinitionSQLConstants.DELETE_CREDENTIALS)) {
                    ps.setString(1, presentationDefinition.getDefinitionId());
                    ps.executeUpdate();
                }
                insertCredentials(connection, presentationDefinition.getDefinitionId(),
                        presentationDefinition.getRequestedCredentials());
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
    public List<ConnectedConnectionInfo> getConnectedConnections(String definitionId, int tenantId)
            throws PresentationManagementException {

        List<ConnectedConnectionInfo> connections = new ArrayList<>();
        String connsSql = PresentationDefinitionSQLConstants.GET_CONNECTED_CONNECTIONS;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(connsSql)) {
            ps.setString(1, definitionId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    connections.add(new ConnectedConnectionInfo(
                            rs.getString(Constants.COL_CONNECTION_ID),
                            rs.getString(Constants.COL_CONNECTION_NAME)));
                }
            }
        } catch (SQLException e) {
            throw new PresentationManagementServerException(
                    PresentationManagementErrorCode.DATABASE_ERROR,
                    "Error fetching connections using presentation definition: " + definitionId, e);
        }
        return connections;
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
            try (PreparedStatement ps = connection.prepareStatement(
                    PresentationDefinitionSQLConstants.SELECT_DEFINITION_BY_IDENTIFIER)) {
                ps.setString(1, identifier);
                ps.setInt(2, tenantId);
                try (ResultSet rs = ps.executeQuery()) {
                    return buildSingleDefinition(rs);
                }
            }
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
        if (databaseName.contains(Constants.MICROSOFT)) {
            return String.format(Constants.GET_PD_LIST_MSSQL, limit)
                    + filterQuery
                    + String.format(Constants.GET_PD_LIST_TAIL_MSSQL, tenantId, safeSortOrder);
        } else if (databaseName.contains(Constants.ORACLE)) {
            return Constants.GET_PD_LIST + filterQuery
                    + String.format(Constants.GET_PD_LIST_TAIL_ORACLE,
                        tenantId, safeSortOrder, limit);
        }
        return Constants.GET_PD_LIST + filterQuery
                + String.format(Constants.GET_PD_LIST_TAIL, tenantId, safeSortOrder, limit);
    }

    /**
     * Inserts the given list of requested credentials into {@code IDN_PD_CREDENTIAL}
     * under the supplied definition ID, using a JDBC batch execute.
     *
     * @param connection   the active database connection with an open transaction
     * @param definitionId the ID of the parent presentation definition
     * @param credentials  the list of requested credentials to persist; no-op when null or empty
     * @throws SQLException if any JDBC operation fails
     */
    private void insertCredentials(Connection connection, String definitionId,
            List<RequestedCredential> credentials) throws SQLException {

        if (credentials == null || credentials.isEmpty()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(PresentationDefinitionSQLConstants.INSERT_CREDENTIAL)) {
            for (RequestedCredential cred : credentials) {
                ps.setString(1, definitionId);
                ps.setString(2, cred.getCredentialId());
                ps.setString(3, cred.getType());
                ps.setString(4, cred.getFormat());
                ps.setString(5, serializeClaimConstraints(cred.getClaims()));
                ps.setString(6, cred.isEnforceTrustedIssuer() ? Constants.FLAG_TRUE : Constants.FLAG_FALSE);
                ps.setString(7, encodeCertBlob(cred.getTrustedCas()));
                ps.setString(8, cred.getKeyResolutionMethod());
                ps.setString(9, cred.getJwksUri());
                ps.setString(10, cred.getIssuerPem());
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    /**
     * Reads a single {@link PresentationDefinition} with its associated credentials from
     * the given result set, where the first row carries the definition metadata and
     * subsequent rows carry additional credential columns from the LEFT JOIN.
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
        List<RequestedCredential> credentials = new ArrayList<>();

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
                credentials.add(mapCredentialRow(rs));
            }
        }

        if (definitionId == null) {
            return null;
        }
        return new PresentationDefinition.Builder()
                .definitionId(definitionId)
                .identifier(identifier)
                .displayName(displayName)
                .description(description)
                .tenantId(tenantId)
                .requestedCredentials(credentials)
                .build();
    }

    /**
     * Reads all {@link PresentationDefinition} instances with their associated credentials from
     * the given result set, grouping credential rows by definition ID.
     *
     * @param rs the result set positioned before the first row
     * @return an ordered list of assembled {@link PresentationDefinition} instances
     * @throws SQLException if reading any column from the result set fails
     */
    private List<PresentationDefinition> buildDefinitionList(ResultSet rs) throws SQLException {

        Map<String, PresentationDefinition.Builder> builders = new LinkedHashMap<>();
        Map<String, List<RequestedCredential>> credentialsMap = new LinkedHashMap<>();

        while (rs.next()) {
            String definitionId = rs.getString(Constants.COL_DEFINITION_ID);
            if (!builders.containsKey(definitionId)) {
                builders.put(definitionId, new PresentationDefinition.Builder()
                        .definitionId(definitionId)
                        .identifier(rs.getString(Constants.COL_IDENTIFIER))
                        .displayName(rs.getString(Constants.COL_DISPLAY_NAME))
                        .description(rs.getString(Constants.COL_DESCRIPTION))
                        .tenantId(rs.getInt(Constants.COL_TENANT_ID)));
                credentialsMap.put(definitionId, new ArrayList<>());
            }
            String credentialId = rs.getString(Constants.COL_CREDENTIAL_ID);
            if (credentialId != null) {
                credentialsMap.get(definitionId).add(mapCredentialRow(rs));
            }
        }

        List<PresentationDefinition> result = new ArrayList<>();
        for (Map.Entry<String, PresentationDefinition.Builder> builderEntry : builders.entrySet()) {
            result.add(builderEntry.getValue()
                    .requestedCredentials(credentialsMap.get(builderEntry.getKey()))
                    .build());
        }
        return result;
    }

    /**
     * Maps the credential columns of the current result set row to a {@link RequestedCredential}.
     *
     * @param rs the result set positioned at the row to map
     * @return a {@link RequestedCredential} populated from the current row
     * @throws SQLException if reading any column from the result set fails
     */
    private RequestedCredential mapCredentialRow(ResultSet rs) throws SQLException {

        RequestedCredential cred = new RequestedCredential();
        cred.setCredentialId(rs.getString(Constants.COL_CREDENTIAL_ID));
        cred.setType(rs.getString(Constants.COL_CREDENTIAL_TYPE));
        cred.setFormat(rs.getString(Constants.COL_CREDENTIAL_FORMAT));
        List<ClaimConstraint> claims = GSON.fromJson(rs.getString(Constants.COL_CLAIMS), CLAIM_CONSTRAINT_LIST_TYPE);
        cred.setClaims(claims != null ? claims : new ArrayList<>());
        cred.setEnforceTrustedIssuer(!Constants.FLAG_FALSE.equals(rs.getString(Constants.COL_ENFORCE_TRUSTED_ISSUER)));
        cred.setTrustedCas(decodeCertBlob(rs.getString(Constants.COL_TRUSTED_CAS)));
        String keyResolutionMethod = rs.getString(Constants.COL_KEY_RESOLUTION_METHOD);
        cred.setKeyResolutionMethod(
                keyResolutionMethod != null ? keyResolutionMethod : VPConstants.DEFAULT_KEY_RESOLUTION_METHOD);
        cred.setJwksUri(rs.getString(Constants.COL_JWKS_URI));
        cred.setIssuerPem(rs.getString(Constants.COL_ISSUER_PEM));
        return cred;
    }

    /**
     * Serialises the given list of claim constraints to a JSON string for storage.
     *
     * @param claims the claim constraints to serialise; may be null or empty
     * @return the JSON representation of the constraints, or {@code null} if the list is null or empty
     */
    private String serializeClaimConstraints(List<ClaimConstraint> claims) {

        if (claims == null || claims.isEmpty()) {
            return null;
        }
        return GSON.toJson(claims);
    }

    /**
     * Concatenates the given PEM certificate strings and encodes the result as a base64
     * UTF-8 string suitable for storage in a single text column.
     *
     * @param certs the list of PEM-formatted certificate strings; may be null or empty
     * @return the base64-encoded concatenated PEM blob, or {@code null} if the list is null or empty
     */
    private String encodeCertBlob(List<String> certs) {

        if (certs == null || certs.isEmpty()) {
            return null;
        }
        StringBuilder pemBuilder = new StringBuilder();
        for (String cert : certs) {
            pemBuilder.append(cert);
            if (!cert.endsWith("\n")) {
                pemBuilder.append("\n");
            }
        }
        return Base64.getEncoder().encodeToString(pemBuilder.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decodes a base64 certificate blob back into a list of individual PEM certificate strings.
     * Uses a regex to extract each {@code -----BEGIN CERTIFICATE-----…-----END CERTIFICATE-----} block.
     *
     * @param encodedCertBlob the base64-encoded PEM blob stored in the database; may be null or blank
     * @return the list of PEM certificate strings, or an empty list if the blob is null or blank
     */
    private List<String> decodeCertBlob(String encodedCertBlob) {

        if (encodedCertBlob == null || encodedCertBlob.trim().isEmpty()) {
            return new ArrayList<>();
        }
        String decodedPem = new String(Base64.getDecoder().decode(encodedCertBlob), StandardCharsets.UTF_8);
        List<String> certs = new ArrayList<>();
        Matcher matcher = PEM_PATTERN.matcher(decodedPem);
        while (matcher.find()) {
            certs.add(matcher.group().trim());
        }
        return certs;
    }
}
