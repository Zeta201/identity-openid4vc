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

package org.wso2.carbon.identity.openid4vc.presentation.core.dto;

import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSessionStatus;

/**
 * DTO returned by the final-result endpoint ({@link
 * org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationSessionService
 * #getPresentationSessionResult}).
 * Carries the session status, the full verification result on success, or the error details on failure.
 * For the lightweight polling endpoint use {@link VPSessionStatusRespDTO}.
 */
public class VPVerificationResultDTO {

    /** Unique identifier of the VP session. */
    private String requestId;
    /** Status of the VP session (e.g. {@code VERIFIED}, {@code FAILED}). */
    private VPSessionStatus status;
    /** Unix timestamp (milliseconds) after which the session is considered expired. */
    private long expiresAt;
    /** Full verification outcome; non-null only when {@code status} is {@code VERIFIED}. */
    private VerificationResponseDTO verificationResponse;
    /** Machine-readable error type; non-null only when {@code status} is {@code FAILED}. */
    private String errorType;
    /** Human-readable error description; non-null only when {@code status} is {@code FAILED}. */
    private String errorDescription;

    public VPVerificationResultDTO() {

    }

    public String getRequestId() {

        return requestId;
    }

    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    public long getExpiresAt() {

        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {

        this.expiresAt = expiresAt;
    }

    public VPSessionStatus getStatus() {

        return status;
    }

    public void setStatus(VPSessionStatus status) {

        this.status = status;
    }

    public VerificationResponseDTO getVerificationResponse() {

        return verificationResponse;
    }

    public void setVerificationResponse(VerificationResponseDTO verificationResponse) {

        this.verificationResponse = verificationResponse;
    }

    public String getErrorType() {

        return errorType;
    }

    public void setErrorType(String errorType) {

        this.errorType = errorType;
    }

    public String getErrorDescription() {

        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {

        this.errorDescription = errorDescription;
    }
}
