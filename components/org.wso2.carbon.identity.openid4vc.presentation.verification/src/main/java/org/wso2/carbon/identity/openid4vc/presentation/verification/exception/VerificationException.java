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
 * Base exception type for credential verification related failures.
 *
 * <p>All subclasses must supply a {@link VerificationErrorCode} so that every failure carries
 * a structured, machine-readable code, a protocol error type, and a human-readable
 * description. Constructors that omit the error code are intentionally absent.</p>
 */
public class VerificationException extends Exception {

    private final VerificationErrorCode errorCode;
    private final String description;

    /**
     * Creates a new exception with the given error code and a short message.
     * The description is taken from {@link VerificationErrorCode#getDescription()}.
     *
     * @param errorCode the structured error code (must not be null)
     * @param message   a concise, developer-facing message
     */
    public VerificationException(VerificationErrorCode errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
        this.description = errorCode.getDescription();
    }

    /**
     * Creates a new exception with the given error code, message, and root cause.
     * The description is taken from {@link VerificationErrorCode#getDescription()}.
     *
     * @param errorCode the structured error code (must not be null)
     * @param message   a concise, developer-facing message
     * @param cause     the underlying exception
     */
    public VerificationException(VerificationErrorCode errorCode, String message, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = errorCode.getDescription();
    }

    /**
     * Creates a new exception with the given error code, message, and a custom description.
     *
     * @param errorCode   the structured error code (must not be null)
     * @param message     a concise, developer-facing message
     * @param description a detailed, user-facing description that overrides the code's default
     */
    public VerificationException(VerificationErrorCode errorCode, String message, String description) {

        super(message);
        this.errorCode = errorCode;
        this.description = description;
    }

    /**
     * Creates a new exception with the given error code, message, custom description, and root cause.
     *
     * @param errorCode   the structured error code (must not be null)
     * @param message     a concise, developer-facing message
     * @param description a detailed, user-facing description that overrides the code's default
     * @param cause       the underlying exception
     */
    public VerificationException(VerificationErrorCode errorCode, String message, String description,
                                 Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    /**
     * Returns the structured error code associated with this exception.
     *
     * @return the {@link VerificationErrorCode}
     */
    public VerificationErrorCode getErrorCode() {

        return errorCode;
    }

    /**
     * Returns the internal error code string (e.g., {@code VPV-60001}).
     *
     * @return internal error code string
     */
    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    /**
     * Returns the error description.
     *
     * @return error description
     */
    public String getDescription() {

        return description;
    }
}
