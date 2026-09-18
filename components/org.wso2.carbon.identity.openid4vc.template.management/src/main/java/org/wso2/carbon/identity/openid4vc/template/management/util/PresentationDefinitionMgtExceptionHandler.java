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

package org.wso2.carbon.identity.openid4vc.template.management.util;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementServerException;

/**
 * Utility class for presentation definition management exception handling.
 */
public class PresentationDefinitionMgtExceptionHandler {

    private PresentationDefinitionMgtExceptionHandler() {

    }

    /**
     * Handle presentation definition management client exceptions.
     *
     * @param error Error message.
     * @param data  Data.
     * @return PresentationManagementClientException.
     */
    public static PresentationManagementClientException handleClientException(
            PresentationDefinitionManagementConstants.ErrorMessages error, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }
        return new PresentationManagementClientException(error.getMessage(), description, error.getCode());
    }

    /**
     * Handle presentation definition management server exceptions.
     *
     * @param error Error message.
     * @param e     Throwable.
     * @param data  Data.
     * @return PresentationManagementServerException.
     */
    public static PresentationManagementServerException handleServerException(
            PresentationDefinitionManagementConstants.ErrorMessages error, Throwable e, Object... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }
        return new PresentationManagementServerException(error.getMessage(), description, error.getCode(), e);
    }
}
