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

package org.wso2.carbon.identity.openid4vc.presentation.core.response;

import com.google.gson.Gson;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSessionStatus;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents the JSON response payload returned when a completed VP verification result is fetched.
 */
public class VPVerificationResultResponse {

    private static final Gson GSON = new Gson();
    private final Map<String, Object> payload;

    private VPVerificationResultResponse(Map<String, Object> payload) {

        this.payload = payload;
    }

    public String toJson() {

        return GSON.toJson(payload);
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder for {@link VPVerificationResultResponse}.
     */
    public static class Builder {

        private final Map<String, Object> payload = new LinkedHashMap<>();

        public Builder status(VPSessionStatus status) {

            if (status != null) {
                payload.put("status", status.getValue());
            }
            return this;
        }

        public Builder errorType(String errorType) {

            if (errorType != null) {
                payload.put("errorType", errorType);
            }
            return this;
        }

        public Builder errorDescription(String errorDescription) {

            if (errorDescription != null) {
                payload.put("errorDescription", errorDescription);
            }
            return this;
        }

        public Builder verificationResponse(VerificationResponseDTO verificationResponse) {

            if (verificationResponse != null) {
                payload.put("verificationResponse", verificationResponse);
            }
            return this;
        }

        public VPVerificationResultResponse build() {

            return new VPVerificationResultResponse(payload);
        }
    }
}
