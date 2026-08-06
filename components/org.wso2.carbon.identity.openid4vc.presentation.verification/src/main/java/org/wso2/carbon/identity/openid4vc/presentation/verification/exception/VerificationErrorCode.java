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

package org.wso2.carbon.identity.openid4vc.presentation.verification.exception;

/**
 * Enum representing error codes for credential verification operations.
 * Error codes follow a standardized format VPV-XXXXX.
 */
public enum VerificationErrorCode {

    // Client errors (4xx)
    INVALID_VP_SUBMISSION("VPV-40001", "invalid_vp_submission",
            "Invalid VP submission.",
            "The Verifiable Presentation submission is invalid or malformed."),
    INVALID_PRESENTATION_DEFINITION("VPV-40002", "invalid_presentation_definition",
            "Invalid presentation definition.",
            "The presentation definition is missing or invalid."),
    INVALID_VP_FORMAT("VPV-40003", "invalid_vp_format",
            "Invalid VP format.",
            "The Verifiable Presentation format is not supported or is invalid."),
    INVALID_SIGNATURE("VPV-40004", "invalid_signature",
            "Invalid signature.",
            "The signature of the Verifiable Presentation or Verifiable Credential is invalid."),
    EXPIRED_CREDENTIAL("VPV-40005", "expired_credential",
            "Expired credential.",
            "The Verifiable Credential has expired."),
    REVOKED_CREDENTIAL("VPV-40006", "revoked_credential",
            "Revoked credential.",
            "The Verifiable Credential has been revoked."),
    INVALID_CREDENTIAL("VPV-40007", "invalid_credential",
            "Invalid credential.",
            "The Verifiable Credential is invalid or malformed."),
    NONCE_MISMATCH("VPV-40008", "nonce_mismatch",
            "Nonce mismatch.",
            "The nonce in the Verifiable Presentation does not match the expected nonce."),
    PARSE_ERROR("VPV-40009", "parse_error",
            "Parse error.",
            "An error occurred while parsing the Verifiable Presentation or Verifiable Credential."),

    // Server errors (5xx)
    INTERNAL_SERVER_ERROR("VPV-50001", "server_error",
            "Internal server error.",
            "An internal server error occurred while processing the verification request."),
    JWKS_RESOLUTION_ERROR("VPV-50003", "jwks_resolution_error",
            "JWKS resolution error.",
            "An error occurred while resolving the JSON Web Key Set (JWKS).");

    private final String code;
    private final String errorType;
    private final String message;
    private final String description;

        /**
         * Creates an error-code entry with internal and protocol-facing details.
         *
         * @param code Internal error code in {@code VPV-XXXXX} format
         * @param errorType Protocol error type value
         * @param message Short error summary
         * @param description Detailed, user-facing error description
         */
    VerificationErrorCode(String code, String errorType, String message, String description) {

        this.code = code;
        this.errorType = errorType;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the internal error code (e.g., VPV-40001).
     *
     * @return Internal error code.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get the error type (e.g., invalid_vp_submission).
     *
     * @return Error type.
     */
    public String getErrorType() {

        return errorType;
    }

    /**
     * Get the error message.
     *
     * @return Error message.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get the error description.
     *
     * @return Error description.
     */
    public String getDescription() {

        return description;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Returns a compact representation containing the internal code and message.</p>
     *
     * @return A string in the form {@code <code> - <message>}
     */
    @Override
    public String toString() {

        return code + " - " + message;
    }
}
