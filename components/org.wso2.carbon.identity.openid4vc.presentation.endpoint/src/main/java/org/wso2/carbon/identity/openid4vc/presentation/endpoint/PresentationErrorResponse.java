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
 * Represents an error response for OpenID4VP endpoints as per OpenID4VP specification.
 */
public class PresentationErrorResponse {

    private static final Gson GSON = new Gson();

    private String error;
    private String errorDescription;

    private PresentationErrorResponse(String error, String errorDescription) {

        this.error = error;
        this.errorDescription = errorDescription;
    }

    public String toJson() {

        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("error", error);
        if (errorDescription != null && !errorDescription.isEmpty()) {
            payload.put("error_description", errorDescription);
        }
        return GSON.toJson(payload);
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder for constructing PresentationErrorResponse instances.
     */
    public static class Builder {

        private String error;
        private String errorDescription;

        public Builder error(String error) {

            this.error = error;
            return this;
        }

        public Builder errorDescription(String errorDescription) {

            this.errorDescription = errorDescription;
            return this;
        }

        public PresentationErrorResponse build() {

            if (error == null || error.isEmpty()) {
                throw new IllegalArgumentException("Error code is required");
            }
            return new PresentationErrorResponse(error, errorDescription);
        }
    }
}
