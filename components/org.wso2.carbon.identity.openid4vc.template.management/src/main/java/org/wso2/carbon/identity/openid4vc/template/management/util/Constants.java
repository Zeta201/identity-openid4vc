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

package org.wso2.carbon.identity.openid4vc.template.management.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Constants for Presentation Definition management.
 */
public class Constants {

    private Constants() {

    }

    // DB column names — IDN_PRESENTATION_DEFINITION.
    public static final String COL_DEFINITION_ID = "ID";
    public static final String COL_TENANT_ID = "TENANT_ID";
    public static final String COL_IDENTIFIER = "IDENTIFIER";
    public static final String COL_DISPLAY_NAME = "DISPLAY_NAME";
    public static final String COL_DESCRIPTION = "DESCRIPTION";
    public static final String COL_CURSOR_KEY = "CURSOR_KEY";

    // DB column names — IDN_PD_CREDENTIAL.
    public static final String COL_CREDENTIAL_ID = "CREDENTIAL_ID";
    public static final String COL_CREDENTIAL_TYPE = "CREDENTIAL_TYPE";
    public static final String COL_CREDENTIAL_FORMAT = "CREDENTIAL_FORMAT";

    // DB column names — IDN_PD_ISSUER_CONFIG.
    public static final String COL_KEY_SOURCE_TYPE = "KEY_SOURCE_TYPE";
    public static final String COL_ISSUER_URL = "ISSUER_URL";
    public static final String COL_KEY_SOURCE = "KEY_SOURCE";

    // DB column names — IDN_PD_CLAIM.
    public static final String COL_CLAIM_PATH = "CLAIM_PATH";
    public static final String COL_IS_MANDATORY = "IS_MANDATORY";

    // DB column aliases — GET_CONNECTED_CONNECTIONS query.
    public static final String COL_CONNECTION_ID = "connection_id";
    public static final String COL_CONNECTION_NAME = "connection_name";

    // SQL state prefix for unique/duplicate key constraint violations.
    public static final String SQL_STATE_CONSTRAINT_VIOLATION_PREFIX = "23";

    // Validation patterns.
    public static final String CREDENTIAL_ID_PATTERN = "^[A-Za-z0-9_-]+$";
    public static final String IDENTIFIER_PATTERN = "^[A-Za-z0-9_-]+$";

    // Pagination constants.
    public static final String AFTER = "after";
    public static final String BEFORE = "before";
    public static final String BEFORE_LT = "before lt ";
    public static final String AFTER_GT = "after gt ";
    public static final String ASC_SORT_ORDER = "ASC";
    public static final String DESC_SORT_ORDER = "DESC";

    // Filter operation constants.
    public static final String EQ = "eq";
    public static final String SW = "sw";
    public static final String EW = "ew";
    public static final String CO = "co";
    public static final String GE = "ge";
    public static final String LE = "le";
    public static final String GT = "gt";
    public static final String LT = "lt";

    /**
     * Attribute to database column mapping for filter expressions.
     * Supports filtering on identifier, displayName, and description; after/before map to the cursor key.
     */
    public static final Map<String, String> ATTRIBUTE_COLUMN_MAP = Collections.unmodifiableMap(
            new HashMap<String, String>() {
                {
                    put("identifier", COL_IDENTIFIER);
                    put("displayName", COL_DISPLAY_NAME);
                    put("description", COL_DESCRIPTION);
                    put(AFTER, COL_CURSOR_KEY);
                    put(BEFORE, COL_CURSOR_KEY);
                }
            });

    // SQL query fragments for paginated list.
    public static final String GET_PD_LIST =
            "SELECT ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_LIST_MSSQL =
            "SELECT TOP(%d) ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_LIST_TAIL =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s LIMIT %d";
    public static final String GET_PD_LIST_TAIL_MSSQL =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s";
    public static final String GET_PD_LIST_TAIL_ORACLE =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s FETCH FIRST %d ROWS ONLY";
    public static final String GET_PD_COUNT =
            "SELECT COUNT(DISTINCT(ID)) FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_COUNT_TAIL =
            " TENANT_ID = ?";
}
