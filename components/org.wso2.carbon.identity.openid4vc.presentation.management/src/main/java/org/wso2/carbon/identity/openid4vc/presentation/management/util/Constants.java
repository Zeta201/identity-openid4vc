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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Constants for Presentation Definition management.
 */
public class Constants {

    private Constants() {

    }

    // DB column names.
    public static final String CURSOR_KEY_COLUMN_NAME = "CURSOR_KEY";
    public static final String NAME_COLUMN_NAME = "NAME";
    public static final String DESCRIPTION_COLUMN_NAME = "DESCRIPTION";
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
     * Supports filtering on name and description; after/before map to the cursor key.
     */
    public static final Map<String, String> ATTRIBUTE_COLUMN_MAP = Collections.unmodifiableMap(
            new HashMap<String, String>() {
                {
                    put("name", NAME_COLUMN_NAME);
                    put("description", DESCRIPTION_COLUMN_NAME);
                    put(AFTER, CURSOR_KEY_COLUMN_NAME);
                    put(BEFORE, CURSOR_KEY_COLUMN_NAME);
                }
            });

    // SQL query fragments for paginated list.
    public static final String GET_PD_LIST =
            "SELECT DEFINITION_ID, CURSOR_KEY, NAME, DESCRIPTION FROM IDN_PRESENTATION_DEFINITION WHERE ";
    public static final String GET_PD_LIST_MSSQL =
            "SELECT TOP(%d) DEFINITION_ID, CURSOR_KEY, NAME, DESCRIPTION FROM IDN_PRESENTATION_DEFINITION WHERE ";
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
