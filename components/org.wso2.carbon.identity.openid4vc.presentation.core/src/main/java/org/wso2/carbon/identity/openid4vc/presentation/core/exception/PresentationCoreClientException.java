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
 * Exception type for client-side presentation core errors.
 *
 * <p>Represents a 4xx-class error where the client submitted an invalid or
 * unprocessable request. Every instance must carry a {@link PresentationCoreErrorCode}.</p>
 */
public class PresentationCoreClientException extends PresentationCoreException {

    public PresentationCoreClientException(PresentationCoreErrorCode errorCode, String message) {

        super(errorCode, message);
    }

    public PresentationCoreClientException(PresentationCoreErrorCode errorCode, String message,
                                           Throwable cause) {

        super(errorCode, message, cause);
    }

    public PresentationCoreClientException(PresentationCoreErrorCode errorCode, String message,
                                          String description) {

        super(errorCode, message, description);
    }

    public PresentationCoreClientException(PresentationCoreErrorCode errorCode, String message,
                                          String description, Throwable cause) {

        super(errorCode, message, description, cause);
    }
}
