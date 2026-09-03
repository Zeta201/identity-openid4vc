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

package org.wso2.carbon.identity.openid4vc.template.management.constant;

/**
 * SQL queries for Presentation Definition management.
 */
public final class PresentationDefinitionSQLConstants {

    private PresentationDefinitionSQLConstants() {

    }

    public static final String INSERT_DEFINITION =
            "INSERT INTO IDN_PRESENTATION_DEFINITION " +
            "(ID, IDENTIFIER, DISPLAY_NAME, DESCRIPTION, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String INSERT_CREDENTIAL =
            "INSERT INTO IDN_PD_CREDENTIAL " +
            "(DEFINITION_ID, IDENTIFIER, CREDENTIAL_TYPE, CREDENTIAL_FORMAT, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String INSERT_ISSUER_CONFIG =
            "INSERT INTO IDN_PD_ISSUER_CONFIG " +
            "(CREDENTIAL_ID, KEY_SOURCE_TYPE, ISSUER_URL, KEY_SOURCE, TENANT_ID) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String SELECT_ISSUER_CONFIGS =
            "SELECT KEY_SOURCE_TYPE, ISSUER_URL, KEY_SOURCE " +
            "FROM IDN_PD_ISSUER_CONFIG WHERE CREDENTIAL_ID = ?";

    public static final String DELETE_ISSUER_CONFIGS_FOR_CREDENTIAL =
            "DELETE FROM IDN_PD_ISSUER_CONFIG WHERE CREDENTIAL_ID = ?";

    public static final String INSERT_CLAIM =
            "INSERT INTO IDN_PD_CLAIM " +
            "(CREDENTIAL_ID, CLAIM_PATH, IS_MANDATORY, TENANT_ID) " +
            "VALUES (?, ?, ?, ?)";

    public static final String SELECT_DEFINITION_BY_ID =
            "SELECT pd.ID, pd.IDENTIFIER, pd.DISPLAY_NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.IDENTIFIER AS CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, " +
            "cl.CLAIM_PATH, cl.IS_MANDATORY " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.ID = c.DEFINITION_ID " +
            "LEFT JOIN IDN_PD_CLAIM cl ON c.ID = cl.CREDENTIAL_ID " +
            "WHERE pd.ID = ? AND pd.TENANT_ID = ?";

    public static final String SELECT_ALL_DEFINITIONS =
            "SELECT pd.ID, pd.IDENTIFIER, pd.DISPLAY_NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.IDENTIFIER AS CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, " +
            "cl.CLAIM_PATH, cl.IS_MANDATORY " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.ID = c.DEFINITION_ID " +
            "LEFT JOIN IDN_PD_CLAIM cl ON c.ID = cl.CREDENTIAL_ID " +
            "WHERE pd.TENANT_ID = ?";

    public static final String SELECT_DEFINITION_BY_IDENTIFIER =
            "SELECT pd.ID, pd.IDENTIFIER, pd.DISPLAY_NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.IDENTIFIER AS CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, " +
            "cl.CLAIM_PATH, cl.IS_MANDATORY " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.ID = c.DEFINITION_ID " +
            "LEFT JOIN IDN_PD_CLAIM cl ON c.ID = cl.CREDENTIAL_ID " +
            "WHERE pd.IDENTIFIER = ? AND pd.TENANT_ID = ?";

    public static final String UPDATE_DEFINITION =
            "UPDATE IDN_PRESENTATION_DEFINITION SET DISPLAY_NAME = ?, DESCRIPTION = ? " +
            "WHERE ID = ? AND TENANT_ID = ?";

    public static final String SELECT_CREDENTIAL_IDS =
            "SELECT ID, IDENTIFIER FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    public static final String DELETE_REMOVED_CREDENTIALS_PREFIX =
            "DELETE FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ? AND ID NOT IN (";

    public static final String UPDATE_CREDENTIAL =
            "UPDATE IDN_PD_CREDENTIAL " +
            "SET CREDENTIAL_TYPE = ?, CREDENTIAL_FORMAT = ? " +
            "WHERE ID = ?";

    public static final String DELETE_CLAIMS_FOR_CREDENTIAL =
            "DELETE FROM IDN_PD_CLAIM WHERE CREDENTIAL_ID = ?";

    public static final String DELETE_CREDENTIALS =
            "DELETE FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    public static final String DELETE_DEFINITION =
            "DELETE FROM IDN_PRESENTATION_DEFINITION WHERE ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_DEFINITION =
            "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_DEFINITION_BY_IDENTIFIER =
            "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE IDENTIFIER = ? AND TENANT_ID = ?";

    public static final String PROP_KEY_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";

    public static final String COUNT_CONNECTIONS_USING_DEFINITION =
            "SELECT COUNT(*) FROM IDP_AUTHENTICATOR_PROPERTY " +
            "WHERE PROPERTY_KEY = '" + PROP_KEY_PRESENTATION_DEFINITION_ID + "' " +
            "AND PROPERTY_VALUE = ? AND TENANT_ID = ?";

    public static final String DELETE_STALE_IDP_CLAIMS_PREFIX =
            "DELETE FROM IDP_CLAIM WHERE TENANT_ID = ? AND CLAIM IN (";

    public static final String DELETE_STALE_IDP_CLAIMS_SUFFIX =
            ") AND IDP_ID IN (" +
            "SELECT auth.IDP_ID FROM IDP_AUTHENTICATOR_PROPERTY prop " +
            "JOIN IDP_AUTHENTICATOR auth ON prop.AUTHENTICATOR_ID = auth.ID " +
            "WHERE prop.PROPERTY_KEY = '" + PROP_KEY_PRESENTATION_DEFINITION_ID + "' " +
            "AND prop.PROPERTY_VALUE = ? AND prop.TENANT_ID = ?)";

    public static final String GET_CONNECTED_CONNECTIONS =
            "SELECT idp.UUID AS connection_id, COALESCE(idp.DISPLAY_NAME, idp.NAME) AS connection_name " +
            "FROM IDP_AUTHENTICATOR_PROPERTY prop " +
            "JOIN IDP_AUTHENTICATOR auth ON prop.AUTHENTICATOR_ID = auth.ID " +
            "JOIN IDP ON auth.IDP_ID = IDP.ID " +
            "WHERE prop.PROPERTY_KEY = '" + PROP_KEY_PRESENTATION_DEFINITION_ID + "' " +
            "AND prop.PROPERTY_VALUE = ? AND prop.TENANT_ID = ?";
}
