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
import org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants;
import org.wso2.carbon.identity.openid4vc.template.management.constant.SQLConstants;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.KeyResolutionMethod;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationClaim;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterQueryBuilder;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionFilterUtil;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionMgtExceptionHandler;

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

import static org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants.ErrorMessages.ERROR_CODE_DATABASE_ERROR;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants.ErrorMessages.ERROR_CODE_DEFINITION_ALREADY_EXISTS;
import static org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants.ErrorMessages.ERROR_CODE_VALIDATION_ERROR;

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
                try (PreparedStatement ps = connection.prepareStatement(SQLConstants.INSERT_DEFINITION)) {
                    ps.setString(1, presentationDefinition.getId());
                    ps.setString(2, presentationDefinition.getIdentifier());
                    ps.setString(3, presentationDefinition.getDisplayName());
                    ps.setString(4, presentationDefinition.getDescription());
                    ps.setInt(5, presentationDefinition.getTenantId());
                    ps.executeUpdate();
                }
                insertCredentials(connection, presentationDefinition.getId(),
                        presentationDefinition.getCredentials(), presentationDefinition.getTenantId());
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                if (e.getSQLState() != null &&
                        e.getSQLState().startsWith(
                                PresentationDefinitionManagementConstants.SQL_STATE_CONSTRAINT_VIOLATION_PREFIX)) {
                    throw PresentationDefinitionMgtExceptionHandler.handleClientException(
                            ERROR_CODE_DEFINITION_ALREADY_EXISTS,
                            presentationDefinition.getIdentifier());
                }
                throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                        ERROR_CODE_DATABASE_ERROR, e);
            }
        } catch (PresentationManagementClientException e) {
            throw e;
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionById(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            PresentationDefinition definition;
            try (PreparedStatement ps = connection.prepareStatement(SQLConstants.GET_DEFINITION_BY_ID)) {
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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public List<PresentationDefinition> getAllPresentationDefinitions(int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            List<PresentationDefinition> definitions;
            try (PreparedStatement ps = connection.prepareStatement(SQLConstants.LIST_DEFINITIONS)) {
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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public void updatePresentationDefinition(PresentationDefinition presentationDefinition,
            List<String> staleClaimPaths, int tenantId) throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                try (PreparedStatement ps = connection.prepareStatement(SQLConstants.UPDATE_DEFINITION)) {
                    ps.setString(1, presentationDefinition.getDisplayName());
                    ps.setString(2, presentationDefinition.getDescription());
                    ps.setString(3, presentationDefinition.getId());
                    ps.setInt(4, presentationDefinition.getTenantId());
                    ps.executeUpdate();
                }
                upsertCredentials(connection, presentationDefinition.getId(),
                        presentationDefinition.getCredentials(), tenantId);
                if (staleClaimPaths != null && !staleClaimPaths.isEmpty()) {
                    String placeholders = String.join(",",
                            Collections.nCopies(staleClaimPaths.size(), "?"));
                    String sql = SQLConstants.DELETE_STALE_IDP_CLAIMS_PREFIX + placeholders
                            + SQLConstants.DELETE_STALE_IDP_CLAIMS_SUFFIX;
                    try (PreparedStatement ps = connection.prepareStatement(sql)) {
                        int i = 1;
                        ps.setInt(i++, tenantId);
                        for (String path : staleClaimPaths) {
                            ps.setString(i++, path);
                        }
                        ps.setString(i++, presentationDefinition.getId());
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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public void deletePresentationDefinition(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try {
                try (PreparedStatement ps = connection.prepareStatement(SQLConstants.DELETE_DEFINITION)) {
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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public boolean presentationDefinitionExists(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(SQLConstants.EXISTS_DEFINITION_BY_ID)) {
            ps.setString(1, definitionId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
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
                String sqlStmt = buildListSql(databaseName, tenantId,
                        filterQueryBuilder.getFilterQuery(), sortOrder, limit);

                try (PreparedStatement ps = connection.prepareStatement(sqlStmt)) {
                    if (filterAttributeValue != null) {
                        for (Map.Entry<Integer, String> entry : filterAttributeValue.entrySet()) {
                            ps.setString(entry.getKey(), entry.getValue());
                        }
                    }
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            PresentationDefinition definition = new PresentationDefinition.Builder()
                                    .id(rs.getString(PresentationDefinitionManagementConstants.COL_DEFINITION_ID))
                                    .cursorKey(rs.getInt(PresentationDefinitionManagementConstants.COL_CURSOR_KEY))
                                    .identifier(rs.getString(PresentationDefinitionManagementConstants.COL_IDENTIFIER))
                                    .displayName(rs.getString(
                                            PresentationDefinitionManagementConstants.COL_DISPLAY_NAME))
                                    .description(rs.getString(
                                            PresentationDefinitionManagementConstants.COL_DESCRIPTION))
                                    .tenantId(tenantId)
                                    .build();
                            results.add(definition);
                        }
                    }
                }
            }
        } catch (PresentationManagementClientException e) {
            throw e;
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
        return results;
    }

    @Override
    public Integer getDefinitionsCount(Integer tenantId, List<ExpressionNode> expressionNodes)
            throws PresentationManagementException {

        try {
            List<ExpressionNode> expressionNodesCopy = new ArrayList<>(expressionNodes);
            expressionNodesCopy.removeIf(expressionNode ->
                    PresentationDefinitionManagementConstants.AFTER.equals(
                            expressionNode.getAttributeValue()) ||
                    PresentationDefinitionManagementConstants.BEFORE.equals(
                            expressionNode.getAttributeValue()));

            PresentationDefinitionFilterQueryBuilder filterQueryBuilder =
                    PresentationDefinitionFilterUtil.getFilterQueryBuilder(expressionNodesCopy);
            Map<Integer, String> filterAttributeValue = filterQueryBuilder.getFilterAttributeValue();

            String sqlStmt = SQLConstants.GET_DEFINITIONS_COUNT
                    + filterQueryBuilder.getFilterQuery()
                    + SQLConstants.GET_DEFINITIONS_COUNT_TAIL;

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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
        return 0;
    }

    @Override
    public boolean isDefinitionInUse(String definitionId, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(
                     SQLConstants.GET_CONNECTION_COUNT_BY_DEFINITION_ID)) {
            ps.setString(1, definitionId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public Map<String, String> getConnectedIdps(String definitionId, int tenantId)
            throws PresentationManagementException {

        Map<String, String> idps = new LinkedHashMap<>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(SQLConstants.LIST_CONNECTIONS_BY_DEFINITION_ID)) {
            ps.setString(1, definitionId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    idps.put(rs.getString(PresentationDefinitionManagementConstants.COL_CONNECTION_ID),
                            rs.getString(PresentationDefinitionManagementConstants.COL_CONNECTION_NAME));
                }
            }
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
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
        String sql = SQLConstants.DELETE_STALE_IDP_CLAIMS_PREFIX + placeholders
                + SQLConstants.DELETE_STALE_IDP_CLAIMS_SUFFIX;

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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public PresentationDefinition getPresentationDefinitionByIdentifier(String identifier, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            PresentationDefinition definition;
            try (PreparedStatement ps = connection.prepareStatement(
                    SQLConstants.GET_DEFINITION_BY_IDENTIFIER)) {
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
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public boolean presentationDefinitionIdentifierExists(String identifier, int tenantId)
            throws PresentationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(
                     SQLConstants.EXISTS_DEFINITION_BY_IDENTIFIER)) {
            ps.setString(1, identifier);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    @Override
    public void replaceIssuerConfigs(String definitionId, String credentialIdentifier,
            List<Issuer> issuers, int tenantId)
            throws PresentationManagementException {

        if (issuers == null || issuers.isEmpty()) {
            throw PresentationDefinitionMgtExceptionHandler.handleClientException(
                    ERROR_CODE_VALIDATION_ERROR,
                    "At least one issuer configuration is required for credential '" +
                            credentialIdentifier + "'.");
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            Map<String, Integer> existingIds = loadCredentialIds(connection, definitionId);
            Integer credentialDbId = existingIds.get(credentialIdentifier);
            if (credentialDbId == null) {
                throw PresentationDefinitionMgtExceptionHandler.handleClientException(
                        ERROR_CODE_VALIDATION_ERROR,
                        "Credential '" + credentialIdentifier + "' not found in definition '" +
                                definitionId + "'.");
            }
            try {
                try (PreparedStatement ps = connection.prepareStatement(
                        SQLConstants.DELETE_ISSUER_CONFIGS_BY_CREDENTIAL_ID)) {
                    ps.setInt(1, credentialDbId);
                    ps.executeUpdate();
                }
                insertIssuerConfigs(connection, credentialDbId, issuers, tenantId);
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw e;
            }
        } catch (PresentationManagementClientException e) {
            throw e;
        } catch (SQLException e) {
            throw PresentationDefinitionMgtExceptionHandler.handleServerException(
                    ERROR_CODE_DATABASE_ERROR, e);
        }
    }

    private String buildListSql(String databaseName, Integer tenantId, String filterQuery,
            String sortOrder, Integer limit) {

        String safeSortOrder = PresentationDefinitionManagementConstants.DESC_SORT_ORDER
                .equalsIgnoreCase(sortOrder)
                ? PresentationDefinitionManagementConstants.DESC_SORT_ORDER
                : PresentationDefinitionManagementConstants.ASC_SORT_ORDER;
        if (databaseName.contains(SQLConstants.MICROSOFT)) {
            return String.format(SQLConstants.GET_DEFINITIONS_MSSQL, limit)
                    + filterQuery
                    + String.format(SQLConstants.GET_DEFINITIONS_TAIL_MSSQL, tenantId, safeSortOrder);
        } else if (databaseName.contains(SQLConstants.ORACLE)) {
            return SQLConstants.GET_DEFINITIONS + filterQuery
                    + String.format(SQLConstants.GET_DEFINITIONS_TAIL_ORACLE, tenantId, safeSortOrder, limit);
        }
        return SQLConstants.GET_DEFINITIONS + filterQuery
                + String.format(SQLConstants.GET_DEFINITIONS_TAIL, tenantId, safeSortOrder, limit);
    }

    private void upsertCredentials(Connection connection, String definitionId,
            List<Credential> credentials, int tenantId) throws SQLException {

        if (credentials == null || credentials.isEmpty()) {
            try (PreparedStatement ps = connection.prepareStatement(SQLConstants.DELETE_CREDENTIALS_BY_DEFINITION_ID)) {
                ps.setString(1, definitionId);
                ps.executeUpdate();
            }
            return;
        }

        Map<String, Integer> existingIds = loadCredentialIds(connection, definitionId);
        List<Integer> keptIds = new ArrayList<>();

        for (Credential cred : credentials) {
            Integer existingId = existingIds.get(cred.getIdentifier());
            int credentialDbId;

            if (existingId != null) {
                try (PreparedStatement ps = connection.prepareStatement(SQLConstants.UPDATE_CREDENTIAL)) {
                    ps.setString(1, cred.getType());
                    ps.setString(2, cred.getFormat());
                    ps.setInt(3, existingId);
                    ps.executeUpdate();
                }
                credentialDbId = existingId;
            } else {
                try (PreparedStatement ps = connection.prepareStatement(
                        SQLConstants.INSERT_CREDENTIAL, Statement.RETURN_GENERATED_KEYS)) {
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
                insertIssuerConfigs(connection, credentialDbId, cred.getIssuers(), tenantId);
            }
            keptIds.add(credentialDbId);
            replaceClaimsForCredential(connection, credentialDbId, cred.getClaims(), tenantId);
        }

        deleteRemovedCredentials(connection, definitionId, keptIds);
    }

    private Map<String, Integer> loadCredentialIds(Connection connection,
            String definitionId) throws SQLException {

        Map<String, Integer> idMap = new LinkedHashMap<>();
        try (PreparedStatement ps = connection.prepareStatement(SQLConstants.LIST_CREDENTIAL_IDS_BY_DEFINITION_ID)) {
            ps.setString(1, definitionId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    idMap.put(rs.getString(PresentationDefinitionManagementConstants.COL_IDENTIFIER),
                            rs.getInt(PresentationDefinitionManagementConstants.COL_DEFINITION_ID));
                }
            }
        }
        return idMap;
    }

    private void replaceClaimsForCredential(Connection connection, int credentialDbId,
            List<PresentationClaim> claims, int tenantId) throws SQLException {

        try (PreparedStatement ps = connection.prepareStatement(
                SQLConstants.DELETE_CLAIMS_BY_CREDENTIAL_ID)) {
            ps.setInt(1, credentialDbId);
            ps.executeUpdate();
        }
        insertClaims(connection, credentialDbId, claims, tenantId);
    }

    private void deleteRemovedCredentials(Connection connection, String definitionId,
            List<Integer> keptIds) throws SQLException {

        String placeholders = String.join(",", Collections.nCopies(keptIds.size(), "?"));
        String sql = SQLConstants.DELETE_REMOVED_CREDENTIALS_PREFIX + placeholders + ")";
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
     */
    private void insertCredentials(Connection connection, String definitionId,
            List<Credential> credentials, int tenantId) throws SQLException {

        if (credentials == null || credentials.isEmpty()) {
            return;
        }
        for (Credential cred : credentials) {
            try (PreparedStatement ps = connection.prepareStatement(
                    SQLConstants.INSERT_CREDENTIAL, Statement.RETURN_GENERATED_KEYS)) {
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
                insertIssuerConfigs(connection, credentialDbId, cred.getIssuers(), tenantId);
            }
        }
    }

    private void insertIssuerConfigs(Connection connection, int credentialDbId,
            List<Issuer> issuers, int tenantId) throws SQLException {

        if (issuers == null || issuers.isEmpty()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(SQLConstants.INSERT_ISSUER_CONFIG)) {
            for (Issuer config : issuers) {
                ps.setInt(1, credentialDbId);
                ps.setString(2, config.getKeyResolutionMethod().name());
                ps.setString(3, config.getIssuerUrl());
                String keySource = config.getKeyResolutionMethod() == KeyResolutionMethod.JWKS_URI
                        ? config.getJwksUri() : config.getCertificate();
                ps.setString(4, keySource);
                ps.setInt(5, tenantId);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    private List<Issuer> loadIssuerConfigs(Connection connection, int credentialDbId) throws SQLException {

        List<Issuer> configs = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(SQLConstants.LIST_ISSUER_CONFIGS_BY_CREDENTIAL_ID)) {
            ps.setInt(1, credentialDbId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Issuer config = new Issuer();
                    KeyResolutionMethod method = KeyResolutionMethod.valueOf(
                            rs.getString(PresentationDefinitionManagementConstants.COL_KEY_SOURCE_TYPE).toUpperCase());
                    config.setKeyResolutionMethod(method);
                    config.setIssuerUrl(rs.getString(PresentationDefinitionManagementConstants.COL_ISSUER_URL));
                    String keySource = rs.getString(PresentationDefinitionManagementConstants.COL_KEY_SOURCE);
                    if (method == KeyResolutionMethod.JWKS_URI) {
                        config.setJwksUri(keySource);
                    } else {
                        config.setCertificate(keySource);
                    }
                    configs.add(config);
                }
            }
        }
        return configs;
    }

    private void loadIssuerConfigsForDefinition(Connection connection,
            PresentationDefinition definition) throws SQLException {

        List<Credential> credentials = definition.getCredentials();
        if (credentials == null || credentials.isEmpty()) {
            return;
        }
        Map<String, Integer> credentialIds = loadCredentialIds(connection, definition.getId());
        for (Credential cred : credentials) {
            Integer credentialDbId = credentialIds.get(cred.getIdentifier());
            if (credentialDbId != null) {
                cred.setIssuers(loadIssuerConfigs(connection, credentialDbId));
            }
        }
    }

    /**
     * Inserts the claim constraints for a single credential into {@code IDN_PD_CLAIM},
     * using a JDBC batch execute. No-op when {@code claims} is null or empty.
     */
    private void insertClaims(Connection connection, int credentialDbId,
            List<PresentationClaim> claims, int tenantId) throws SQLException {

        if (claims == null || claims.isEmpty()) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement(SQLConstants.INSERT_PD_CLAIM)) {
            for (PresentationClaim claim : claims) {
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
     */
    private PresentationDefinition buildSingleDefinition(ResultSet rs) throws SQLException {

        String definitionId = null;
        String identifier = null;
        String displayName = null;
        String description = null;
        int tenantId = 0;
        Map<String, Credential> credMap = new LinkedHashMap<>();
        Map<String, List<PresentationClaim>> claimsMap = new LinkedHashMap<>();

        while (rs.next()) {
            if (definitionId == null) {
                definitionId = rs.getString(PresentationDefinitionManagementConstants.COL_DEFINITION_ID);
                identifier = rs.getString(PresentationDefinitionManagementConstants.COL_IDENTIFIER);
                displayName = rs.getString(PresentationDefinitionManagementConstants.COL_DISPLAY_NAME);
                description = rs.getString(PresentationDefinitionManagementConstants.COL_DESCRIPTION);
                tenantId = rs.getInt(PresentationDefinitionManagementConstants.COL_TENANT_ID);
            }
            String credentialId = rs.getString(PresentationDefinitionManagementConstants.COL_CREDENTIAL_ID);
            if (credentialId != null) {
                if (!credMap.containsKey(credentialId)) {
                    credMap.put(credentialId, mapCredentialRow(rs));
                    claimsMap.put(credentialId, new ArrayList<>());
                }
                if (rs.getString(PresentationDefinitionManagementConstants.COL_CLAIM_PATH) != null) {
                    claimsMap.get(credentialId).add(mapClaimRow(rs));
                }
            }
        }

        if (definitionId == null) {
            return null;
        }
        for (Map.Entry<String, Credential> entry : credMap.entrySet()) {
            entry.getValue().setClaims(claimsMap.get(entry.getKey()));
        }
        return new PresentationDefinition.Builder()
                .id(definitionId)
                .identifier(identifier)
                .displayName(displayName)
                .description(description)
                .tenantId(tenantId)
                .credentials(new ArrayList<>(credMap.values()))
                .build();
    }

    /**
     * Reads all {@link PresentationDefinition} instances with their credentials and claim
     * constraints from the given result set. Each row represents a (credential, claim) pair;
     * rows are grouped first by definition ID, then by credential ID, accumulating claims
     * per credential.
     */
    private List<PresentationDefinition> buildDefinitionList(ResultSet rs) throws SQLException {

        Map<String, PresentationDefinition.Builder> builders = new LinkedHashMap<>();
        Map<String, Map<String, Credential>> credsByDef = new LinkedHashMap<>();
        Map<String, List<PresentationClaim>> claimsByCredential = new LinkedHashMap<>();

        while (rs.next()) {
            String definitionId = rs.getString(PresentationDefinitionManagementConstants.COL_DEFINITION_ID);
            if (!builders.containsKey(definitionId)) {
                builders.put(definitionId, new PresentationDefinition.Builder()
                        .id(definitionId)
                        .identifier(rs.getString(PresentationDefinitionManagementConstants.COL_IDENTIFIER))
                        .displayName(rs.getString(PresentationDefinitionManagementConstants.COL_DISPLAY_NAME))
                        .description(rs.getString(PresentationDefinitionManagementConstants.COL_DESCRIPTION))
                        .tenantId(rs.getInt(PresentationDefinitionManagementConstants.COL_TENANT_ID)));
                credsByDef.put(definitionId, new LinkedHashMap<>());
            }
            String credentialId = rs.getString(PresentationDefinitionManagementConstants.COL_CREDENTIAL_ID);
            if (credentialId != null) {
                String compositeKey = definitionId + "|" + credentialId;
                if (!credsByDef.get(definitionId).containsKey(credentialId)) {
                    credsByDef.get(definitionId).put(credentialId, mapCredentialRow(rs));
                    claimsByCredential.put(compositeKey, new ArrayList<>());
                }
                if (rs.getString(PresentationDefinitionManagementConstants.COL_CLAIM_PATH) != null) {
                    claimsByCredential.get(compositeKey).add(mapClaimRow(rs));
                }
            }
        }

        List<PresentationDefinition> result = new ArrayList<>();
        for (Map.Entry<String, PresentationDefinition.Builder> builderEntry : builders.entrySet()) {
            String definitionId = builderEntry.getKey();
            Map<String, Credential> creds = credsByDef.get(definitionId);
            for (Map.Entry<String, Credential> credEntry : creds.entrySet()) {
                credEntry.getValue().setClaims(
                        claimsByCredential.get(definitionId + "|" + credEntry.getKey()));
            }
            result.add(builderEntry.getValue()
                    .credentials(new ArrayList<>(creds.values()))
                    .build());
        }
        return result;
    }

    /**
     * Maps the credential columns of the current result set row to a {@link Credential}.
     */
    private Credential mapCredentialRow(ResultSet rs) throws SQLException {

        Credential cred = new Credential();
        cred.setIdentifier(rs.getString(PresentationDefinitionManagementConstants.COL_CREDENTIAL_ID));
        cred.setType(rs.getString(PresentationDefinitionManagementConstants.COL_CREDENTIAL_TYPE));
        cred.setFormat(rs.getString(PresentationDefinitionManagementConstants.COL_CREDENTIAL_FORMAT));
        return cred;
    }

    /**
     * Maps the claim columns of the current result set row to a {@link PresentationClaim}.
     */
    private PresentationClaim mapClaimRow(ResultSet rs) throws SQLException {

        PresentationClaim claim = new PresentationClaim();
        claim.setPath(rs.getString(PresentationDefinitionManagementConstants.COL_CLAIM_PATH));
        claim.setMandatory(rs.getBoolean(PresentationDefinitionManagementConstants.COL_IS_MANDATORY));
        return claim;
    }
}
