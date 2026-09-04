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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

/**
 * Represents an OpenID4VP authorization request issued to the wallet.
 * Holds all protocol-level fields required to construct and track a VP request lifecycle,
 * including the signed request JWT, the response endpoint, and the current flow status.
 * Use {@link Builder} to construct instances.
 */
public class VPAuthorizationRequest {

    private String requestId;
    private String clientId;
    private String nonce;
    private String presentationDefinitionId;
    private String responseUri;
    private String responseMode;
    private String requestJwt;
    private VPFlowStatus status;
    private long expiresAt;
    private String requestUri;

    private VPAuthorizationRequest(Builder builder) {

        this.requestId = builder.requestId;
        this.clientId = builder.clientId;
        this.nonce = builder.nonce;
        this.presentationDefinitionId = builder.presentationDefinitionId;
        this.responseUri = builder.responseUri;
        this.responseMode = builder.responseMode;
        this.requestJwt = builder.requestJwt;
        this.status = builder.status;
        this.expiresAt = builder.expiresAt;
        this.requestUri = builder.requestUri;
    }

    public String getRequestId() {

        return requestId;
    }

    public String getClientId() {

        return clientId;
    }

    public String getNonce() {

        return nonce;
    }

    public String getPresentationDefinitionId() {

        return presentationDefinitionId;
    }

    public String getResponseUri() {

        return responseUri;
    }

    public String getResponseMode() {

        return responseMode;
    }

    public String getRequestJwt() {

        return requestJwt;
    }

    public VPFlowStatus getStatus() {

        return status;
    }

    public long getExpiresAt() {

        return expiresAt;
    }

    public String getRequestUri() {

        return requestUri;
    }

    @Override
    public String toString() {

        return "VPAuthorizationRequest{requestId='" + requestId + '\'' + ", clientId='" + clientId + '\''
                + ", status=" + status + ", expiresAt=" + expiresAt + '}';
    }

    /**
     * Builder for {@link VPAuthorizationRequest}.
     */
    public static class Builder {

        private String requestId;
        private String clientId;
        private String nonce;
        private String presentationDefinitionId;
        private String responseUri;
        private String responseMode;
        private String requestJwt;
        private VPFlowStatus status;
        private long expiresAt;
        private String requestUri;

        public Builder requestId(String requestId) {

            this.requestId = requestId;
            return this;
        }

        public Builder clientId(String clientId) {

            this.clientId = clientId;
            return this;
        }

        public Builder nonce(String nonce) {

            this.nonce = nonce;
            return this;
        }

        public Builder presentationDefinitionId(String presentationDefinitionId) {

            this.presentationDefinitionId = presentationDefinitionId;
            return this;
        }

        public Builder responseUri(String responseUri) {

            this.responseUri = responseUri;
            return this;
        }

        public Builder responseMode(String responseMode) {

            this.responseMode = responseMode;
            return this;
        }

        public Builder requestJwt(String requestJwt) {

            this.requestJwt = requestJwt;
            return this;
        }

        public Builder status(VPFlowStatus status) {

            this.status = status;
            return this;
        }

        public Builder expiresAt(long expiresAt) {

            this.expiresAt = expiresAt;
            return this;
        }

        public Builder requestUri(String requestUri) {

            this.requestUri = requestUri;
            return this;
        }

        /**
         * Constructs a {@link VPAuthorizationRequest} from the values set on this builder.
         *
         * @return a new {@link VPAuthorizationRequest} instance
         */
        public VPAuthorizationRequest build() {

            return new VPAuthorizationRequest(this);
        }
    }
}
