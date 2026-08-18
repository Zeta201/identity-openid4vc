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

package org.wso2.carbon.identity.openid4vc.presentation.management.util;

/**
 * SQL queries for Presentation Definition management.
 */
public class SQLQueries {

    private SQLQueries() {

    }

    public static final String INSERT_DEFINITION =
            "INSERT INTO IDN_PRESENTATION_DEFINITION (DEFINITION_ID, NAME, DESCRIPTION, TENANT_ID) " +
            "VALUES (?, ?, ?, ?)";

    public static final String INSERT_CREDENTIAL =
            "INSERT INTO IDN_PD_CREDENTIAL " +
            "(DEFINITION_ID, CREDENTIAL_ID, CREDENTIAL_TYPE, CREDENTIAL_FORMAT, CLAIMS, " +
            "ENFORCE_TRUSTED_ISSUER, TRUSTED_CAS, KEY_RESOLUTION_METHOD, JWKS_URI, ISSUER_PEM) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    public static final String SELECT_DEFINITION_BY_ID =
            "SELECT pd.DEFINITION_ID, pd.NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, c.CLAIMS, " +
            "c.ENFORCE_TRUSTED_ISSUER, c.TRUSTED_CAS, " +
            "c.KEY_RESOLUTION_METHOD, c.JWKS_URI, c.ISSUER_PEM " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.DEFINITION_ID = c.DEFINITION_ID " +
            "WHERE pd.DEFINITION_ID = ? AND pd.TENANT_ID = ?";

    public static final String SELECT_ALL_DEFINITIONS =
            "SELECT pd.DEFINITION_ID, pd.NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, c.CLAIMS, " +
            "c.ENFORCE_TRUSTED_ISSUER, c.TRUSTED_CAS, " +
            "c.KEY_RESOLUTION_METHOD, c.JWKS_URI, c.ISSUER_PEM " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.DEFINITION_ID = c.DEFINITION_ID " +
            "WHERE pd.TENANT_ID = ?";

    public static final String SELECT_DEFINITION_BY_NAME =
            "SELECT pd.DEFINITION_ID, pd.NAME, pd.DESCRIPTION, pd.TENANT_ID, " +
            "c.CREDENTIAL_ID, c.CREDENTIAL_TYPE, c.CREDENTIAL_FORMAT, c.CLAIMS, " +
            "c.ENFORCE_TRUSTED_ISSUER, c.TRUSTED_CAS, " +
            "c.KEY_RESOLUTION_METHOD, c.JWKS_URI, c.ISSUER_PEM " +
            "FROM IDN_PRESENTATION_DEFINITION pd " +
            "LEFT JOIN IDN_PD_CREDENTIAL c ON pd.DEFINITION_ID = c.DEFINITION_ID " +
            "WHERE pd.NAME = ? AND pd.TENANT_ID = ?";

    public static final String UPDATE_DEFINITION =
            "UPDATE IDN_PRESENTATION_DEFINITION SET NAME = ?, DESCRIPTION = ? " +
            "WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    public static final String DELETE_CREDENTIALS =
            "DELETE FROM IDN_PD_CREDENTIAL WHERE DEFINITION_ID = ?";

    public static final String DELETE_DEFINITION =
            "DELETE FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    public static final String EXISTS_DEFINITION =
            "SELECT 1 FROM IDN_PRESENTATION_DEFINITION WHERE DEFINITION_ID = ? AND TENANT_ID = ?";

    public static final String COUNT_CONNECTIONS_USING_DEFINITION =
            "SELECT COUNT(*) FROM IDP_AUTHENTICATOR_PROPERTY " +
            "WHERE PROPERTY_KEY = 'presentationDefinitionId' AND PROPERTY_VALUE = ? AND TENANT_ID = ?";

    public static final String DELETE_STALE_IDP_CLAIMS_PREFIX =
            "DELETE FROM IDP_CLAIM WHERE TENANT_ID = ? AND CLAIM IN (";

    public static final String DELETE_STALE_IDP_CLAIMS_SUFFIX =
            ") AND IDP_ID IN (" +
            "SELECT auth.IDP_ID FROM IDP_AUTHENTICATOR_PROPERTY prop " +
            "JOIN IDP_AUTHENTICATOR auth ON prop.AUTHENTICATOR_ID = auth.ID " +
            "WHERE prop.PROPERTY_KEY = 'presentationDefinitionId' " +
            "AND prop.PROPERTY_VALUE = ? AND prop.TENANT_ID = ?)";

    public static final String GET_CONNECTED_CONNECTIONS =
            "SELECT idp.UUID AS connection_id, COALESCE(idp.DISPLAY_NAME, idp.NAME) AS connection_name " +
            "FROM IDP_AUTHENTICATOR_PROPERTY prop " +
            "JOIN IDP_AUTHENTICATOR auth ON prop.AUTHENTICATOR_ID = auth.ID " +
            "JOIN IDP ON auth.IDP_ID = IDP.ID " +
            "WHERE prop.PROPERTY_KEY = 'presentationDefinitionId' " +
            "AND prop.PROPERTY_VALUE = ? AND prop.TENANT_ID = ?";
}
