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
    public static final String COL_DEFINITION_ID = "DEFINITION_ID";
    public static final String COL_TENANT_ID = "TENANT_ID";
    public static final String COL_IDENTIFIER = "IDENTIFIER";
    public static final String COL_DISPLAY_NAME = "DISPLAY_NAME";
    public static final String COL_DESCRIPTION = "DESCRIPTION";
    public static final String COL_CURSOR_KEY = "CURSOR_KEY";

    // DB column names — IDN_PD_CREDENTIAL.
    public static final String COL_CREDENTIAL_ID = "CREDENTIAL_ID";
    public static final String COL_CREDENTIAL_TYPE = "CREDENTIAL_TYPE";
    public static final String COL_CREDENTIAL_FORMAT = "CREDENTIAL_FORMAT";
    public static final String COL_CLAIMS = "CLAIMS";
    public static final String COL_ENFORCE_TRUSTED_ISSUER = "ENFORCE_TRUSTED_ISSUER";
    public static final String COL_TRUSTED_CAS = "TRUSTED_CAS";
    public static final String COL_KEY_RESOLUTION_METHOD = "KEY_RESOLUTION_METHOD";
    public static final String COL_JWKS_URI = "JWKS_URI";
    public static final String COL_ISSUER_PEM = "ISSUER_PEM";

    // DB column aliases — GET_CONNECTED_CONNECTIONS query.
    public static final String COL_CONNECTION_ID = "connection_id";
    public static final String COL_CONNECTION_NAME = "connection_name";

    // SQL state prefix for unique/duplicate key constraint violations.
    public static final String SQL_STATE_CONSTRAINT_VIOLATION_PREFIX = "23";

    // Validation patterns.
    public static final String CREDENTIAL_ID_PATTERN = "^[A-Za-z0-9_-]+$";
    public static final String IDENTIFIER_PATTERN = "^[A-Za-z0-9_-]+$";

    // Kept for backward compatibility — prefer COL_* equivalents in new code.
    public static final String CURSOR_KEY_COLUMN_NAME = COL_CURSOR_KEY;
    public static final String DISPLAY_NAME_COLUMN_NAME = COL_DISPLAY_NAME;
    public static final String IDENTIFIER_COLUMN_NAME = COL_IDENTIFIER;
    public static final String DESCRIPTION_COLUMN_NAME = COL_DESCRIPTION;

    public static final String MICROSOFT = "Microsoft";
    public static final String ORACLE = "Oracle";

    // Pagination constants.
    public static final String AFTER = "after";
    public static final String BEFORE = "before";
    public static final String BEFORE_LT = "before lt ";
    public static final String AFTER_GT = "after gt ";
    public static final String ASC_SORT_ORDER = "ASC";
    public static final String DESC_SORT_ORDER = "DESC";
    public static final int DEFAULT_LIMIT = 10;

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
                    put("identifier", IDENTIFIER_COLUMN_NAME);
                    put("displayName", DISPLAY_NAME_COLUMN_NAME);
                    put("description", DESCRIPTION_COLUMN_NAME);
                    put(AFTER, CURSOR_KEY_COLUMN_NAME);
                    put(BEFORE, CURSOR_KEY_COLUMN_NAME);
                }
            });

    // SQL query fragments for paginated list.
    public static final String GET_PD_LIST =
            "SELECT DEFINITION_ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_LIST_MSSQL =
            "SELECT TOP(%d) DEFINITION_ID, CURSOR_KEY, IDENTIFIER, DISPLAY_NAME, DESCRIPTION " +
            "FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_LIST_TAIL =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s LIMIT %d";
    public static final String GET_PD_LIST_TAIL_MSSQL =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s";
    public static final String GET_PD_LIST_TAIL_ORACLE =
            " TENANT_ID = %d ORDER BY CURSOR_KEY %s FETCH FIRST %d ROWS ONLY";
    public static final String GET_PD_COUNT =
            "SELECT COUNT(DISTINCT(DEFINITION_ID)) FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_COUNT_TAIL =
            " TENANT_ID = ?";
}
