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
 * This class represents the base exception for the credential verification module.
 */
public class VerificationException extends Exception {

    private final VerificationErrorCode errorCode;
    private final String description;

    public VerificationException(VerificationErrorCode errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
        this.description = errorCode.getDescription();
    }

    public VerificationException(VerificationErrorCode errorCode, String message, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = errorCode.getDescription();
    }

    public VerificationException(VerificationErrorCode errorCode, String message, String description) {

        super(message);
        this.errorCode = errorCode;
        this.description = description;
    }

    public VerificationException(VerificationErrorCode errorCode, String message, String description,
                                 Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
        this.description = description;
    }

    public VerificationErrorCode getErrorCode() {

        return errorCode;
    }

    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    public String getDescription() {

        return description;
    }
}
