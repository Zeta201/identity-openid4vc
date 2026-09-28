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

package org.wso2.carbon.identity.openid4vc.presentation.core.util;

import org.apache.commons.lang3.ArrayUtils;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;

/**
 * This class builds client and server exceptions for the presentation core module.
 */
public class PresentationCoreExceptionHandler {

    private PresentationCoreExceptionHandler() {

    }

    /**
     * Builds a client exception for the given error code.
     *
     * @param errorCode Structured error code.
     * @param data      Optional format arguments applied to the error code's description.
     * @return Client exception.
     */
    public static PresentationCoreClientException handleClientException(
            PresentationCoreErrorCode errorCode, String... data) {

        String description = errorCode.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, (Object[]) data);
        }
        return new PresentationCoreClientException(errorCode, errorCode.getMessage(), description);
    }

    /**
     * Builds a server exception for the given error code, wrapping a cause.
     *
     * @param errorCode Structured error code.
     * @param cause     Underlying exception, or null if none.
     * @param data      Optional format arguments applied to the error code's description.
     * @return Server exception.
     */
    public static PresentationCoreServerException handleServerException(
            PresentationCoreErrorCode errorCode, Throwable cause, String... data) {

        String description = errorCode.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, (Object[]) data);
        }
        return new PresentationCoreServerException(errorCode, errorCode.getMessage(), description, cause);
    }
}
