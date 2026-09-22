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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

/**
 * Error codes for authenticator client/server exception handling.
 */
public enum PresentationAuthenticatorErrorCode {

    // Client errors (60xxx)
    INVALID_PRESENTATION_DEFINITION("VPA-60001", "invalid_presentation_definition",
            "Invalid presentation definition.", "The presentation definition is invalid or missing."),

    VP_REQUEST_NOT_FOUND("VPA-60002", "vp_request_not_found",
            "VP request was not found.", "The VP request was not found or has expired."),

    VERIFICATION_FAILED("VPA-60003", "verification_failed",
            "VP verification failed.", "The wallet returned a failed verification."),

    NO_VERIFIED_CLAIMS("VPA-60004", "no_verified_claims",
            "No verified claims found.",
            "The VP verification completed but returned no usable subject identifier from the configured claim '%s'."),

    FLOW_ABORTED("VPA-60005", "flow_aborted",
            "VP flow was aborted.", "The VP flow was rolled back or cancelled before completion."),

    // Server errors (65xxx)
    INTERNAL_SERVER_ERROR("VPA-65001", "server_error",
            "Internal server error.", "An internal server error occurred in the authenticator."),

    FEATURE_DISABLED("VPA-65002", "feature_disabled",
            "OpenID4VP feature is disabled.", "Enable it via [openid4vp] enabled=true in deployment.toml."),

    SIGNING_ERROR("VPA-65003", "signing_error",
            "Signing error.", "An error occurred while resolving the server certificate or key."),

    ORG_TENANT_RESOLUTION_ERROR("VPA-65004", "server_error",
            "Tenant domain resolution error.",
            "Failed to resolve tenant domain for organization '%s'."),

    VP_FLOW_INITIATION_ERROR("VPA-65005", "server_error",
            "VP flow initiation error.",
            "An error occurred while initiating the VP presentation session."),

    VP_SESSION_RETRIEVAL_ERROR("VPA-65006", "server_error",
            "VP session retrieval error.",
            "An error occurred while retrieving the VP session for request '%s'.");

    private final String code;
    private final String errorType;
    private final String message;
    private final String description;

    PresentationAuthenticatorErrorCode(String code, String errorType, String message, String description) {

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
}
