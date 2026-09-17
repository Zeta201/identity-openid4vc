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

package org.wso2.carbon.identity.openid4vc.presentation.core.exception;

/**
 * Error codes for presentation core client/server exception handling.
 *
 * <p>Each entry carries four fields:
 * <ul>
 *   <li>{@code code} — internal tracking code (e.g. {@code VPC-60001})</li>
 *   <li>{@code errorType} — protocol-level error type returned in responses</li>
 *   <li>{@code message} — short developer-facing label used as the exception message</li>
 *   <li>{@code description} — longer description; may contain {@code %s} placeholders formatted via
 *       {@link org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreExceptionHandler}</li>
 * </ul>
 */
public enum PresentationCoreErrorCode {

    // Client errors (60xxx)
    INVALID_REQUEST("VPC-60001", "invalid_request",
            "Invalid request.",
            "The request is invalid or malformed."),

    VP_REQUEST_NOT_FOUND("VPC-60002", "vp_request_not_found",
            "VP request not found.",
            "The VP request was not found or has already been consumed."),

    VP_REQUEST_EXPIRED("VPC-60003", "vp_request_expired",
            "VP request expired.",
            "The VP request has expired."),

    PRESENTATION_DEFINITION_NOT_FOUND("VPC-60004", "presentation_definition_not_found",
            "Presentation definition not found.",
            "The presentation definition '%s' was not found."),

    VERIFICATION_FAILED("VPC-60005", "verification_failed",
            "VP verification failed.",
            "The verifiable presentation verification failed."),

    RESPONSE_MODE_MISMATCH("VPC-60006", "invalid_request",
            "Response mode mismatch.",
            "The wallet response mode does not match the mode configured for this session."),

    INVALID_VP_TOKEN("VPC-60007", "invalid_request",
            "Invalid vp_token.",
            "The vp_token is missing, malformed, or does not contain the required credential."),

    // Server errors (65xxx)
    INTERNAL_SERVER_ERROR("VPC-65001", "server_error",
            "Internal server error.",
            "An internal server error occurred."),

    SIGNING_ERROR("VPC-65002", "signing_error",
            "Request signing error.",
            "An error occurred while signing the authorization request object."),

    CONFIG_RETRIEVAL_ERROR("VPC-65004", "server_error",
            "Configuration retrieval error.",
            "An error occurred while retrieving the OpenID4VP tenant configuration."),

    CONFIG_UPDATE_ERROR("VPC-65005", "server_error",
            "Configuration update error.",
            "An error occurred while persisting the OpenID4VP tenant configuration."),

    PRESENTATION_DEFINITION_ERROR("VPC-65006", "server_error",
            "Presentation definition error.",
            "An error occurred while loading the presentation definition."),

    EPHEMERAL_KEY_ERROR("VPC-65007", "server_error",
            "Ephemeral key error.",
            "An error occurred while generating or parsing the ephemeral encryption key."),

    WALLET_RESPONSE_DECRYPTION_ERROR("VPC-65008", "server_error",
            "Wallet response decryption error.",
            "An error occurred while decrypting or parsing the wallet's JWE response."),

    BASE_URL_RESOLUTION_ERROR("VPC-65009", "server_error",
            "Base URL resolution error.",
            "An error occurred while resolving the server base URL."),

    UNSUPPORTED_CLIENT_ID_SCHEME("VPC-65010", "server_error",
            "Unsupported client_id_scheme.",
            "The client_id_scheme '%s' is not supported or is not configured correctly."),

    SIGNING_CERTIFICATE_ERROR("VPC-65011", "signing_error",
            "Signing certificate error.",
            "An error occurred while loading or processing the server's signing certificate."),

    SIGNING_KEY_ERROR("VPC-65012", "signing_error",
            "Signing key error.",
            "An error occurred while accessing or validating the server's signing key.");

    private final String code;
    private final String errorType;
    private final String message;
    private final String description;

    PresentationCoreErrorCode(String errorCode, String errorType,
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
