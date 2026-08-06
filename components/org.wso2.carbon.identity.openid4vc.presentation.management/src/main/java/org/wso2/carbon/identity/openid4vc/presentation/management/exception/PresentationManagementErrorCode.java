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

package org.wso2.carbon.identity.openid4vc.presentation.management.exception;

/**
 * Error codes for presentation definition management operations.
 * Error codes follow the format VPD-XXXXX.
 */
public enum PresentationManagementErrorCode {

    // Client errors (4xx)
    VALIDATION_ERROR("VPD-40001", "invalid_request",
            "Validation error.",
            "The presentation definition request is invalid or missing required fields."),
    DEFINITION_NOT_FOUND("VPD-40401", "definition_not_found",
            "Presentation definition not found.",
            "The requested presentation definition does not exist."),
    DEFINITION_ALREADY_EXISTS("VPD-40901", "definition_already_exists",
            "Presentation definition already exists.",
            "A presentation definition with the same ID or name already exists."),
    DEFINITION_IN_USE("VPD-40902", "definition_in_use",
            "Presentation definition is in use.",
            "The presentation definition is referenced by one or more connections and cannot be deleted."),
    INVALID_FILTER("VPD-40002", "invalid_request",
            "Invalid filter expression.",
            "The filter expression is invalid, uses an unsupported attribute, or an unsupported operation."),
    INVALID_PAGINATION("VPD-40003", "invalid_request",
            "Invalid pagination parameters.",
            "Both 'before' and 'after' pagination cursors cannot be specified at the same time."),

    // Server errors (5xx)
    DATABASE_ERROR("VPD-50001", "server_error",
            "Database error.",
            "A database error occurred while processing the presentation definition request."),
    INTERNAL_SERVER_ERROR("VPD-50002", "server_error",
            "Internal server error.",
            "An internal server error occurred while processing the request.");

    private final String code;
    private final String errorType;
    private final String message;
    private final String description;

    PresentationManagementErrorCode(String code, String errorType, String message, String description) {

        this.code = code;
        this.errorType = errorType;
        this.message = message;
        this.description = description;
    }

    public String getCode() {

        return code;
    }

    public String getErrorType() {

        return errorType;
    }

    public String getMessage() {

        return message;
    }

    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return code + " - " + message;
    }
}
