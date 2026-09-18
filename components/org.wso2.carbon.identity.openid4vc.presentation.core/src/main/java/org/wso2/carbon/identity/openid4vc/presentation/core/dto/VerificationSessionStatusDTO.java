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
 * DTO returned by the VP session status polling endpoint.
 * Carries only the fields a poller needs: session identity, current state,
 * expiry time, and — when the session has failed — the machine-readable error type.
 */
public class VerificationSessionStatusDTO {

    private String requestId;
    private VPSessionStatus status;
    private long expiresAt;
    private String errorType;

    public VerificationSessionStatusDTO() {

    }

    public String getRequestId() {

        return requestId;
    }

    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    public VPSessionStatus getStatus() {

        return status;
    }

    public void setStatus(VPSessionStatus status) {

        this.status = status;
    }

    public long getExpiresAt() {

        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {

        this.expiresAt = expiresAt;
    }

    public String getErrorType() {

        return errorType;
    }

    public void setErrorType(String errorType) {

        this.errorType = errorType;
    }
}
