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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

/**
 * Error codes for presentation authenticator client/server exception handling.
 */
public enum VPAuthenticatorErrorCode {

    INVALID_REQUEST("VPA-40001", "invalid_request",
            "Invalid request.", "Invalid or malformed request."),

    VP_REQUEST_NOT_FOUND("VPA-40401", "vp_request_not_found",
            "VP request was not found.", "The VP request was not found."),

    VP_REQUEST_EXPIRED("VPA-41001", "vp_request_expired",
            "VP request has expired.", "The VP request has expired."),

    INTERNAL_SERVER_ERROR("VPA-50001", "server_error",
            "Internal server error.", "An internal server error occurred."),

    INVALID_PRESENTATION_DEFINITION("VPA-40003", "invalid_presentation_definition",
            "Invalid presentation definition.", "The presentation definition is invalid or missing."),

    CLIENT_METADATA_ERROR("VPA-40004", "invalid_client_metadata",
            "Invalid client metadata.", "The client metadata is invalid or malformed."),

    VERIFICATION_FAILED("VPA-40101", "verification_failed",
            "VP verification failed.", "The verifiable presentation verification failed."),

    SIGNING_ERROR("VPA-50002", "signing_error",
            "Error occurred during signing.", "An error occurred while signing the request object."),

    FEATURE_DISABLED("VPA-40302", "feature_disabled",
            "OpenID4VP feature is disabled.", "Enable it via [openid4vp] enabled=true in deployment.toml."),

    NO_VERIFIED_CLAIMS("VPA-40102", "no_verified_claims",
            "No verified claims found.", "The VP verification completed but returned no verified claims."),

    INVALID_CONFIG("VPA-40005", "invalid_request",
            "Invalid configuration.", "The provided OpenID4VP configuration is invalid or malformed."),

    CONFIG_RETRIEVAL_ERROR("VPA-50003", "server_error",
            "Configuration retrieval error.", "An error occurred while retrieving the OpenID4VP tenant configuration."),

    CONFIG_UPDATE_ERROR("VPA-50004", "server_error",
            "Configuration update error.", "An error occurred while persisting the OpenID4VP tenant configuration.");

    private final String code;
    private final String errorType;
    private final String message;
    private final String description;

    VPAuthenticatorErrorCode(String errorCode, String errorType,
                             String errorMsg, String errorDescription) {

        this.code = errorCode;
        this.errorType = errorType;
        this.message = errorMsg;
        this.description = errorDescription;
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
}
