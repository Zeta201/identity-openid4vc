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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import org.apache.commons.lang3.ArrayUtils;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;

/**
 * Factory for {@link VerificationClientException} and {@link VerificationServerException}.
 *
 * <p>All throw sites in the verification module must go through this handler rather than
 * constructing exceptions directly. This ensures every exception carries a consistent
 * {@link VerificationErrorCode} and that descriptions are formatted uniformly.</p>
 */
public class VerificationExceptionHandler {

    private VerificationExceptionHandler() {

    }

    /**
     * Builds a {@link VerificationClientException} for the given error code.
     *
     * @param errorCode the structured error code
     * @param data      optional {@link String#format} arguments applied to the error code's description
     * @return a fully populated client exception
     */
    public static VerificationClientException handleClientException(
            VerificationErrorCode errorCode, String... data) {

        String description = errorCode.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, (Object[]) data);
        }
        return new VerificationClientException(errorCode, errorCode.getMessage(), description);
    }

    /**
     * Builds a {@link VerificationServerException} for the given error code, wrapping a cause.
     *
     * @param errorCode the structured error code
     * @param cause     the underlying exception
     * @param data      optional {@link String#format} arguments applied to the error code's description
     * @return a fully populated server exception
     */
    public static VerificationServerException handleServerException(
            VerificationErrorCode errorCode, Throwable cause, String... data) {

        String description = errorCode.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, (Object[]) data);
        }
        return new VerificationServerException(errorCode, errorCode.getMessage(), description, cause);
    }

}
