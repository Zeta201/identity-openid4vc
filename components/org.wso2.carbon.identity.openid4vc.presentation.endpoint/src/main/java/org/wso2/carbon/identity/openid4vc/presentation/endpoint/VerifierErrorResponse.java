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

package org.wso2.carbon.identity.openid4vc.presentation.endpoint;

import com.google.gson.Gson;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Error response for verifier-facing REST endpoints, following the WSO2 IS API error convention.
 * Produces {@code { "code", "message", "description", "traceId" }}.
 *
 * <p>Wallet-facing endpoints use {@link PresentationErrorResponse} instead, which follows the
 * OAuth 2.0 / OpenID4VP convention required by the protocol.</p>
 */
public class VerifierErrorResponse {

    private static final Gson GSON = new Gson();

    private String code;
    private String message;
    private String description;
    private String traceId;

    private VerifierErrorResponse(String code, String message, String description, String traceId) {

        this.code = code;
        this.message = message;
        this.description = description;
        this.traceId = traceId;
    }

    public String toJson() {

        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("code", code);
        payload.put("message", message);
        if (description != null && !description.isEmpty()) {
            payload.put("description", description);
        }
        payload.put("traceId", traceId);
        return GSON.toJson(payload);
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder for {@link VerifierErrorResponse}.
     */
    public static class Builder {

        private String code;
        private String message;
        private String description;
        private String traceId;

        public Builder code(String code) {

            this.code = code;
            return this;
        }

        public Builder message(String message) {

            this.message = message;
            return this;
        }

        public Builder description(String description) {

            this.description = description;
            return this;
        }

        public Builder traceId(String traceId) {

            this.traceId = traceId;
            return this;
        }

        public VerifierErrorResponse build() {

            if (code == null || code.isEmpty()) {
                throw new IllegalArgumentException("Error code is required.");
            }
            if (message == null || message.isEmpty()) {
                throw new IllegalArgumentException("Error message is required.");
            }
            String resolvedTraceId = traceId != null ? traceId : PresentationEndpointUtils.getCorrelationId();
            return new VerifierErrorResponse(code, message, description, resolvedTraceId);
        }
    }
}
