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

package org.wso2.carbon.identity.openid4vc.presentation.management.exception;

/**
 * Exception type for client-side presentation management errors.
 * Thrown for invalid requests, missing definitions, duplicate names, etc. (4xx).
 */
public class PresentationManagementClientException extends PresentationManagementException {

    public PresentationManagementClientException(String message) {

        super(message);
    }

    public PresentationManagementClientException(String message, Throwable cause) {

        super(message, cause);
    }

    public PresentationManagementClientException(String message, String description) {

        super(message, description);
    }

    public PresentationManagementClientException(String message, String description, Throwable cause) {

        super(message, description, cause);
    }

    public PresentationManagementClientException(PresentationManagementErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    public PresentationManagementClientException(PresentationManagementErrorCode errorCode, String message,
                                                 Throwable cause) {

        super(errorCode, message, cause);
    }

    public PresentationManagementClientException(PresentationManagementErrorCode errorCode, String message,
                                                 String description) {

        super(errorCode, message, description);
    }

    public PresentationManagementClientException(PresentationManagementErrorCode errorCode, String message,
                                                 String description, Throwable cause) {

        super(errorCode, message, description, cause);
    }
}
