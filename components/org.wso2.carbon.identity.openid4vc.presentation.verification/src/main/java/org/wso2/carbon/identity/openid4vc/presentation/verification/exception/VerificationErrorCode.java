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
 * Error codes for credential verification operations.
 *
 * <p>Each entry carries three fields:
 * <ul>
 *   <li>{@code code} — internal tracking code (e.g. {@code VPV-60001})</li>
 *   <li>{@code message} — short developer-facing label used as the exception message</li>
 *   <li>{@code description} — longer user-facing text; may contain {@code %s} placeholders formatted via
 *       {@link org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationExceptionHandler}</li>
 * </ul>
 */
public enum VerificationErrorCode {

    // Client errors (60xxx)
    INVALID_VP_SUBMISSION("VPV-60001",
            "Invalid VP submission.",
            "The Verifiable Presentation submission is invalid or malformed."),
    INVALID_PRESENTATION_DEFINITION("VPV-60002",
            "Invalid presentation definition.",
            "The presentation definition is missing or invalid."),
    INVALID_VP_FORMAT("VPV-60003",
            "Invalid VP format.",
            "The Verifiable Presentation format is not supported or invalid."),
    INVALID_SIGNATURE("VPV-60004",
            "Invalid signature.",
            "The cryptographic signature of the Verifiable Presentation is invalid."),
    EXPIRED_CREDENTIAL("VPV-60005",
            "Expired credential.",
            "The Verifiable Credential has expired."),
    NONCE_MISMATCH("VPV-60007",
            "Nonce mismatch.",
            "The nonce in the Verifiable Presentation does not match the expected nonce."),
    INVALID_SD_JWT_FORMAT("VPV-60008",
            "Invalid SD-JWT format.",
            "The SD-JWT token is malformed and could not be parsed."),
    INVALID_ISSUER_JWT("VPV-60009",
            "Invalid issuer JWT.",
            "The issuer-signed JWT is malformed or its claims could not be parsed."),
    INVALID_KB_JWT("VPV-60010",
            "Invalid key-binding JWT.",
            "The key-binding JWT is malformed, has the wrong type, or is missing required claims."),
    UNTRUSTED_ISSUER("VPV-60011",
            "Untrusted issuer.",
            "No trusted issuer configuration matches the credential's iss claim."),
    DISCLOSURE_HASH_MISMATCH("VPV-60012",
            "Disclosure hash mismatch.",
            "A disclosure hash does not appear in the issuer's _sd array; the presentation may have been "
                    + "tampered with."),
    CREDENTIAL_TYPE_MISMATCH("VPV-60013",
            "Credential type mismatch.",
            "The vct claim in the credential does not match the expected credential type."),
    MISSING_KEY_BINDING_JWT("VPV-60014",
            "Missing key-binding JWT.",
            "A key-binding JWT is required by the presentation request but was not included in the SD-JWT."),
    INVALID_HOLDER_BINDING("VPV-60015",
            "Invalid holder binding.",
            "The cnf.jwk holder binding is missing, malformed, or contains invalid key material."),
    AUDIENCE_MISMATCH("VPV-60016",
            "Audience mismatch.",
            "The aud claim in the key-binding JWT does not match the expected audience."),
    SD_HASH_MISMATCH("VPV-60017",
            "SD hash mismatch.",
            "The sd_hash in the key-binding JWT does not match the computed hash of the SD-JWT presentation."),
    UNSUPPORTED_SIGNING_ALGORITHM("VPV-60018",
            "Unsupported signing algorithm.",
            "The JWS signing algorithm is not permitted or is not supported."),
    INVALID_X5C_CHAIN("VPV-60019",
            "Invalid x5c certificate chain.",
            "The x5c certificate chain is missing, malformed, self-signed, or does not validate against the "
                    + "trusted CA."),
    CERTIFICATE_NOT_YET_VALID("VPV-60020",
            "Certificate not yet valid.",
            "An X.509 certificate in the chain is not yet valid."),
    STALE_KB_JWT("VPV-60021",
            "Stale key-binding JWT.",
            "The key-binding JWT iat is outside the allowed freshness window."),

    // Server errors (65xxx)
    INTERNAL_SERVER_ERROR("VPV-65001",
            "Internal server error.",
            "An internal server error occurred while processing the verification request."),
    JWKS_RESOLUTION_ERROR("VPV-65002",
            "JWKS resolution error.",
            "An error occurred while fetching or parsing the JSON Web Key Set (JWKS)."),
    ISSUER_NOT_FOUND("VPV-65003",
            "Issuer configuration not found.",
            "No issuer configuration is available for the credential, or the configured JWKS URI is missing "
                    + "or invalid."),
    TRUST_ANCHOR_NOT_CONFIGURED("VPV-65004",
            "Trust anchor not configured.",
            "The trusted CA certificate is not configured for x5c validation."),
    VALIDATOR_NOT_REGISTERED("VPV-65005",
            "Validator not registered.",
            "No signature validator is registered for the configured key resolution method."),
    DISCLOSURE_DIGEST_ERROR("VPV-65006",
            "Disclosure digest error.",
            "An internal error occurred while computing the disclosure hash.");

    private final String code;
    private final String message;
    private final String description;

    VerificationErrorCode(String code, String message, String description) {

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

    @Override
    public String toString() {

        return code + " - " + message;
    }
}
