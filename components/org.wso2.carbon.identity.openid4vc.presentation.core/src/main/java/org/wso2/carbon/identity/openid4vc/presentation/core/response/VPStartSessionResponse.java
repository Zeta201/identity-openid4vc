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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents the JSON response payload returned when a VP verification session is started.
 */
public class VPStartSessionResponse {

    private static final Gson GSON = new Gson();
    private final Map<String, Object> payload;

    private VPStartSessionResponse(Map<String, Object> payload) {

        this.payload = payload;
    }

    public String toJson() {

        return GSON.toJson(payload);
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder for {@link VPStartSessionResponse}.
     */
    public static class Builder {

        private final Map<String, Object> payload = new LinkedHashMap<>();

        public Builder requestId(String requestId) {

            payload.put("requestId", requestId);
            return this;
        }

        public Builder requestUri(String requestUri) {

            payload.put("requestUri", requestUri);
            return this;
        }

        public Builder expiresAt(long expiresAt) {

            payload.put("expiresAt", expiresAt);
            return this;
        }

        public VPStartSessionResponse build() {

            return new VPStartSessionResponse(payload);
        }
    }
}
