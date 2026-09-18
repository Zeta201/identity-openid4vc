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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Constants for Presentation Definition management.
 */
public class PresentationDefinitionManagementConstants {

    private PresentationDefinitionManagementConstants() {

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

    // Validation pattern for identifiers and credential IDs.
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

    /**
     * Error message codes and default messages used in presentation definition management.
     */
    public enum ErrorMessages {

        // Client errors
        ERROR_CODE_VALIDATION_ERROR("VPD-40001", "Validation error.", "%s"),
        ERROR_CODE_DEFINITION_NOT_FOUND("VPD-40401", "Presentation definition not found.",
                "The requested presentation definition '%s' does not exist."),
        ERROR_CODE_DEFINITION_ALREADY_EXISTS("VPD-40901", "Presentation definition already exists.",
                "A presentation definition with identifier '%s' already exists."),
        ERROR_CODE_DEFINITION_IN_USE("VPD-40902", "Presentation definition is in use.",
                "The presentation definition '%s' is referenced by one or more connections and cannot be deleted."),
        ERROR_CODE_INVALID_FILTER("VPD-40002", "Invalid filter expression.", "%s"),
        ERROR_CODE_INVALID_PAGINATION("VPD-40003", "Invalid pagination parameters.",
                "Both 'before' and 'after' pagination cursors cannot be specified at the same time."),

        // Server errors
        ERROR_CODE_DATABASE_ERROR("VPD-50001", "Database error.",
                "A database error occurred while processing the presentation definition request."),
        ERROR_CODE_INTERNAL_SERVER_ERROR("VPD-50002", "Internal server error.",
                "An internal server error occurred while processing the request.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {
            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        public String getDescription() {
            return description;
        }
    }
}
