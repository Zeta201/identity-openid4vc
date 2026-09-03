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

package org.wso2.carbon.identity.openid4vc.template.management.exception;

/**
 * Exception type for server-side presentation management errors.
 * Thrown for database failures, internal errors, etc. (5xx).
 */
public class PresentationManagementServerException extends PresentationManagementException {

    public PresentationManagementServerException(String message) {

        super(message);
    }

    public PresentationManagementServerException(String message, Throwable cause) {

        super(message, cause);
    }

    public PresentationManagementServerException(String message, String description) {

        super(message, description);
    }

    public PresentationManagementServerException(String message, String description, Throwable cause) {

        super(message, description, cause);
    }

    public PresentationManagementServerException(PresentationManagementErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    public PresentationManagementServerException(PresentationManagementErrorCode errorCode, String message,
                                                 Throwable cause) {

        super(errorCode, message, cause);
    }

    public PresentationManagementServerException(PresentationManagementErrorCode errorCode, String message,
                                                 String description) {

        super(errorCode, message, description);
    }

    public PresentationManagementServerException(PresentationManagementErrorCode errorCode, String message,
                                                 String description, Throwable cause) {

        super(errorCode, message, description, cause);
    }
}
