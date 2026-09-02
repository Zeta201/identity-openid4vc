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
 * Base exception type for presentation server failures.
 */
public class VPAuthenticatorException extends Exception {

    private final VPAuthenticatorErrorCode errorCode;
    private final String description;

    public VPAuthenticatorException(String message) {

        super(message);
        this.errorCode = null;
        this.description = null;
    }

    public VPAuthenticatorException(String message, Throwable cause) {

        super(message, cause);
        this.errorCode = null;
        this.description = null;
    }

    public VPAuthenticatorException(VPAuthenticatorErrorCode errorCodeParam, String message) {

        super(message);
        this.errorCode = errorCodeParam;
        this.description = errorCodeParam != null ? errorCodeParam.getDescription() : null;
    }

    public VPAuthenticatorException(VPAuthenticatorErrorCode errorCodeParam, String message,
                                    Throwable cause) {

        super(message, cause);
        this.errorCode = errorCodeParam;
        this.description = errorCodeParam != null ? errorCodeParam.getDescription() : null;
    }

    public VPAuthenticatorException(VPAuthenticatorErrorCode errorCodeParam, String message,
                                    String descriptionParam) {

        super(message);
        this.errorCode = errorCodeParam;
        this.description = descriptionParam;
    }

    public VPAuthenticatorException(VPAuthenticatorErrorCode errorCodeParam, String message,
                                    String descriptionParam, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCodeParam;
        this.description = descriptionParam;
    }

    public VPAuthenticatorErrorCode getErrorCode() {

        return errorCode;
    }

    public String getCode() {

        return errorCode != null ? errorCode.getCode() : null;
    }

    public String getErrorType() {

        return errorCode != null ? errorCode.getErrorType() : null;
    }

    public String getDescription() {

        return description;
    }
}
