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
 * Base exception type for presentation core failures.
 *
 * <p>All subclasses must supply a {@link PresentationCoreErrorCode} so that every failure carries
 * a structured, machine-readable code, a protocol error type, and a human-readable
 * description. Constructors that omit the error code are intentionally absent.</p>
 */
public class PresentationCoreException extends Exception {

    private final PresentationCoreErrorCode errorCode;
    private final String description;

    public PresentationCoreException(PresentationCoreErrorCode errorCodeParam, String message) {

        super(message);
        this.errorCode = errorCodeParam;
        this.description = errorCodeParam != null ? errorCodeParam.getDescription() : null;
    }

    public PresentationCoreException(PresentationCoreErrorCode errorCodeParam, String message,
                                    Throwable cause) {

        super(message, cause);
        this.errorCode = errorCodeParam;
        this.description = errorCodeParam != null ? errorCodeParam.getDescription() : null;
    }

    public PresentationCoreException(PresentationCoreErrorCode errorCodeParam, String message,
                                    String descriptionParam) {

        super(message);
        this.errorCode = errorCodeParam;
        this.description = descriptionParam;
    }

    public PresentationCoreException(PresentationCoreErrorCode errorCodeParam, String message,
                                    String descriptionParam, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCodeParam;
        this.description = descriptionParam;
    }

    public PresentationCoreErrorCode getErrorCode() {

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
