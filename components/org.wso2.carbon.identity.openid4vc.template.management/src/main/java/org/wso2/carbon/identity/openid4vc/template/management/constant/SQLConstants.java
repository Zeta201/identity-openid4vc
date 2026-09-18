/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.template.management.constant;

/**
 * SQL queries used by VC Template DAO.
 */
public final class SQLConstants {

    private SQLConstants() {}

    // DB types.
    public static final String MICROSOFT = "Microsoft";
    public static final String ORACLE = "Oracle";

    // Column names.
    public static final String CURSOR_KEY_COLUMN_NAME = "CURSOR_KEY";
    public static final String IDENTIFIER_COLUMN_NAME = "IDENTIFIER";
    public static final String DISPLAY_NAME_COLUMN_NAME = "DISPLAY_NAME";
    public static final String DESCRIPTION_COLUMN_NAME = "DESCRIPTION";
    public static final String FORMAT_COLUMN_NAME = "FORMAT";

    // IDN_VC_TEMPLATE
    public static final String LIST_TEMPLATES =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_VC_TEMPLATE WHERE TENANT_ID = ? ORDER BY CURSOR_KEY";

    public static final String GET_TEMPLATE_BY_ID =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM IDN_VC_TEMPLATE WHERE ID = ? AND TENANT_ID = ?";

    public static final String GET_TEMPLATE_BY_IDENTIFIER =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM IDN_VC_TEMPLATE WHERE IDENTIFIER = ? AND TENANT_ID = ?";

    public static final String GET_TEMPLATE_BY_OFFER_ID =
            "SELECT ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, SIGNING_ALG, " +
            "EXPIRES_IN, OFFER_ID " +
            "FROM IDN_VC_TEMPLATE WHERE OFFER_ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_BY_IDENTIFIER =
            "SELECT 1 FROM IDN_VC_TEMPLATE WHERE TENANT_ID = ? AND IDENTIFIER = ?";

    public static final String INSERT_TEMPLATE =
            "INSERT INTO IDN_VC_TEMPLATE (ID, TENANT_ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, FORMAT, " +
            "SIGNING_ALG, EXPIRES_IN, OFFER_ID) VALUES " +
            "(?,?,?,?,?,?,?,?,?)";

    public static final String UPDATE_TEMPLATE =
            "UPDATE IDN_VC_TEMPLATE SET IDENTIFIER = ?, DISPLAY_NAME = ?, DESCRIPTION = ?, FORMAT = ?, " +
            "SIGNING_ALG = ?, EXPIRES_IN = ?, OFFER_ID = ? " +
            "WHERE TENANT_ID = ? AND ID = ?";

    public static final String DELETE_TEMPLATE =
            "DELETE FROM IDN_VC_TEMPLATE WHERE TENANT_ID = ? AND ID = ?";

    public static final String UPDATE_OFFER_ID =
            "UPDATE IDN_VC_TEMPLATE SET OFFER_ID = ? WHERE TENANT_ID = ? AND ID = ?";

    // IDN_VC_CLAIMS
    public static final String LIST_CLAIMS_BY_TEMPLATE_ID =
            "SELECT NAME, TYPE, CLAIM_URI FROM IDN_VC_CLAIMS WHERE TEMPLATE_ID = ?";

    public static final String INSERT_CLAIM =
            "INSERT INTO IDN_VC_CLAIMS (TEMPLATE_ID, NAME, TYPE, CLAIM_URI) VALUES (?,?,?,?)";

    public static final String DELETE_CLAIMS_BY_TEMPLATE_ID =
            "DELETE FROM IDN_VC_CLAIMS WHERE TEMPLATE_ID = ?";

    public static final String GET_VC_TEMPLATES = "SELECT ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_VC_TEMPLATE WHERE ";
    public static final String GET_VC_TEMPLATES_MSSQL = "SELECT TOP(%d) ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, " +
            "DESCRIPTION FROM IDN_VC_TEMPLATE WHERE ";
    public static final String GET_VC_TEMPLATES_TAIL = " TENANT_ID = %d ORDER BY CURSOR_KEY %s LIMIT %d";
    public static final String GET_VC_TEMPLATES_TAIL_MSSQL = " TENANT_ID = %d ORDER BY CURSOR_KEY %s";
    public static final String GET_VC_TEMPLATES_TAIL_ORACLE = " TENANT_ID = %d ORDER BY CURSOR_KEY %s " +
            "FETCH FIRST %d ROWS ONLY";
    public static final String GET_VC_TEMPLATES_COUNT = "SELECT COUNT(DISTINCT(ID)) FROM IDN_VC_TEMPLATE WHERE ";
    public static final String GET_VC_TEMPLATES_COUNT_TAIL = " TENANT_ID = ?";

    // Presentation Definition SQL constants.

    // IDN_PRESENTATION_DEFINITION
    public static final String GET_DEFINITIONS =
            "SELECT ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_DEFINITIONS_MSSQL =
            "SELECT TOP(%d) ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_DEFINITIONS_TAIL =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s LIMIT %d";
    public static final String GET_DEFINITIONS_TAIL_MSSQL =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s";
    public static final String GET_DEFINITIONS_TAIL_ORACLE =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s FETCH FIRST %d ROWS ONLY";
    public static final String GET_DEFINITIONS_COUNT =
            "SELECT COUNT(DISTINCT(ID)) FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_DEFINITIONS_COUNT_TAIL =
            " TENANT_ID = ?";

    public static final String INSERT_DEFINITION =
            "INSERT INTO IDN_PRESENTATION_DEFINITION " +
            "(ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String UPDATE_DEFINITION =
            "UPDATE IDN_PRESENTATION_DEFINITION SET DISPLAY_NAME = ?, DESCRIPTION = ? " +
            "WHERE ID = ? AND TENANT_ID = ?";

    public static final String DELETE_DEFINITION =
            "DELETE FROM IDN_PRESENTATION_DEFINITION WHERE ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_DEFINITION_BY_ID =
            "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_DEFINITION_BY_IDENTIFIER =
            "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE IDENTIFIER = ? AND TENANT_ID = ?";

    public static final String GET_DEFINITION_BY_ID =
            "SELECT pd.ID, pd.IDENTIFIER, pd.DISPLAY_NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.IDENTIFIER AS CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, " +
            "cl.CLAIM_PATH, cl.IS_MANDATORY " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.ID = c.DEFINITION_ID " +
            "LEFT JOIN IDN_PD_CLAIM cl ON c.ID = cl.CREDENTIAL_ID " +
            "WHERE pd.ID = ? AND pd.TENANT_ID = ?";

    public static final String LIST_DEFINITIONS =
            "SELECT pd.ID, pd.IDENTIFIER, pd.DISPLAY_NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.IDENTIFIER AS CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, " +
            "cl.CLAIM_PATH, cl.IS_MANDATORY " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.ID = c.DEFINITION_ID " +
            "LEFT JOIN IDN_PD_CLAIM cl ON c.ID = cl.CREDENTIAL_ID " +
            "WHERE pd.TENANT_ID = ?";

    public static final String GET_DEFINITION_BY_IDENTIFIER =
            "SELECT pd.ID, pd.IDENTIFIER, pd.DISPLAY_NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.IDENTIFIER AS CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, " +
            "cl.CLAIM_PATH, cl.IS_MANDATORY " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.ID = c.DEFINITION_ID " +
            "LEFT JOIN IDN_PD_CLAIM cl ON c.ID = cl.CREDENTIAL_ID " +
            "WHERE pd.IDENTIFIER = ? AND pd.TENANT_ID = ?";

    // IDN_PD_CREDENTIAL
    public static final String INSERT_CREDENTIAL =
            "INSERT INTO IDN_PD_CREDENTIAL " +
            "(DEFINITION_ID, IDENTIFIER, CREDENTIAL_TYPE, CREDENTIAL_FORMAT, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String UPDATE_CREDENTIAL =
            "UPDATE IDN_PD_CREDENTIAL " +
            "SET CREDENTIAL_TYPE = ?, CREDENTIAL_FORMAT = ? " +
            "WHERE ID = ?";

    public static final String DELETE_CREDENTIALS_BY_DEFINITION_ID =
            "DELETE FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    public static final String DELETE_REMOVED_CREDENTIALS_PREFIX =
            "DELETE FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ? AND ID NOT IN (";

    public static final String LIST_CREDENTIAL_IDS_BY_DEFINITION_ID =
            "SELECT ID, IDENTIFIER FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    // IDN_PD_ISSUER_CONFIG
    public static final String INSERT_ISSUER_CONFIG =
            "INSERT INTO IDN_PD_ISSUER_CONFIG " +
            "(CREDENTIAL_ID, KEY_SOURCE_TYPE, ISSUER_URL, KEY_SOURCE, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String LIST_ISSUER_CONFIGS_BY_CREDENTIAL_ID =
            "SELECT KEY_SOURCE_TYPE, ISSUER_URL, KEY_SOURCE " +
            "FROM IDN_PD_ISSUER_CONFIG WHERE CREDENTIAL_ID = ?";

    public static final String DELETE_ISSUER_CONFIGS_BY_CREDENTIAL_ID =
            "DELETE FROM IDN_PD_ISSUER_CONFIG WHERE CREDENTIAL_ID = ?";

    // IDN_PD_CLAIM
    public static final String INSERT_PD_CLAIM =
            "INSERT INTO IDN_PD_CLAIM " +
            "(CREDENTIAL_ID, CLAIM_PATH, IS_MANDATORY, TENANT_ID) " +
            "VALUES (?, ?, ?, ?)";

    public static final String DELETE_CLAIMS_BY_CREDENTIAL_ID =
            "DELETE FROM IDN_PD_CLAIM WHERE CREDENTIAL_ID = ?";

    // IDP_AUTHENTICATOR_PROPERTY / IDP_CLAIM / IDP
    public static final String PROP_KEY_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";

    public static final String GET_CONNECTION_COUNT_BY_DEFINITION_ID =
            "SELECT COUNT(*) FROM IDP_AUTHENTICATOR_PROPERTY " +
            "WHERE PROPERTY_KEY = '" + PROP_KEY_PRESENTATION_DEFINITION_ID + "' " +
            "AND PROPERTY_VALUE = ? AND TENANT_ID = ?";

    public static final String LIST_CONNECTIONS_BY_DEFINITION_ID =
            "SELECT idp.UUID AS connection_id, COALESCE(idp.DISPLAY_NAME, idp.NAME) AS connection_name " +
            "FROM IDP_AUTHENTICATOR_PROPERTY prop " +
            "JOIN IDP_AUTHENTICATOR auth ON prop.AUTHENTICATOR_ID = auth.ID " +
            "JOIN IDP ON auth.IDP_ID = IDP.ID " +
            "WHERE prop.PROPERTY_KEY = '" + PROP_KEY_PRESENTATION_DEFINITION_ID + "' " +
            "AND prop.PROPERTY_VALUE = ? AND prop.TENANT_ID = ?";

    public static final String DELETE_STALE_IDP_CLAIMS_PREFIX =
            "DELETE FROM IDP_CLAIM WHERE TENANT_ID = ? AND CLAIM IN (";

    public static final String DELETE_STALE_IDP_CLAIMS_SUFFIX =
            ") AND IDP_ID IN (" +
            "SELECT auth.IDP_ID FROM IDP_AUTHENTICATOR_PROPERTY prop " +
            "JOIN IDP_AUTHENTICATOR auth ON prop.AUTHENTICATOR_ID = auth.ID " +
            "WHERE prop.PROPERTY_KEY = '" + PROP_KEY_PRESENTATION_DEFINITION_ID + "' " +
            "AND prop.PROPERTY_VALUE = ? AND prop.TENANT_ID = ?)";
}
