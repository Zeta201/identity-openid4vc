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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents the JSON response payload returned when a completed VP verification result is fetched.
 */
public class VerificationSessionResultResponse {

    private static final Gson GSON = new Gson();
    private final Map<String, Object> payload;

    private VerificationSessionResultResponse(Map<String, Object> payload) {

        this.payload = payload;
    }

    public String toJson() {

        return GSON.toJson(payload);
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder for {@link VerificationSessionResultResponse}.
     */
    public static class Builder {

        private final Map<String, Object> payload = new LinkedHashMap<>();

        public Builder requestId(String requestId) {

            payload.put("requestId", requestId);
            return this;
        }

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
                Map<String, Object> credential = new LinkedHashMap<>();
                credential.put("vct", verificationResponse.getVct());
                credential.put("format", verificationResponse.getCredentialFormat());
                credential.put("issuer", verificationResponse.getIssuer());
                credential.put("signingAlgorithm", verificationResponse.getSigningAlgorithm());
                credential.put("issuedAt", toIso8601(verificationResponse.getIssuedAt()));
                credential.put("expiresAt", toIso8601(verificationResponse.getExpiresAt()));
                credential.put("claims", verificationResponse.getSubjectClaims());
                payload.put("credential", credential);

                Map<String, Object> keyBinding = new LinkedHashMap<>();
                keyBinding.put("verified", verificationResponse.isKbJwtVerified());
                keyBinding.put("nonce", verificationResponse.getNonce());
                payload.put("keyBinding", keyBinding);

                payload.put("verifiedAt", toIso8601(verificationResponse.getVerifiedAt()));
            }
            return this;
        }

        public VerificationSessionResultResponse build() {

            return new VerificationSessionResultResponse(payload);
        }

        private static String toIso8601(Long epochMillis) {

            return epochMillis == null ? null
                    : Instant.ofEpochMilli(epochMillis).truncatedTo(ChronoUnit.SECONDS).toString();
        }
    }
}
