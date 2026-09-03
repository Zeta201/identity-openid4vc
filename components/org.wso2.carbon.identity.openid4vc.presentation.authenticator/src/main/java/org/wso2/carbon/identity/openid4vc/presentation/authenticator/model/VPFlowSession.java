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

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;

import java.io.Serializable;

/**
 * Represents the server-side state of an active VP authorization flow.
 * Created when a VP request is initiated and updated as the wallet responds.
 * Serializable so it can be stored in the distributed session cache.
 * Use {@link Builder} to construct instances.
 */
public class VPFlowSession implements Serializable {

    private static final long serialVersionUID = 1L;

    private String tenantDomain;
    private int tenantId;
    private VPFlowStatus status;
    private VerificationResult verificationResult;
    private String nonce;
    private String ephemeralPrivateKeyJwk;
    private long expiresAt;
    private String clientId;
    private String clientIdScheme;
    private String responseUri;
    private String responseMode;
    private String walletUrl;
    private DcqlQuery dcqlQuery;
    private String failureReason;

    public String getTenantDomain() {

        return tenantDomain;
    }

    public int getTenantId() {

        return tenantId;
    }

    public VPFlowStatus getStatus() {

        return status;
    }

    public void setStatus(VPFlowStatus status) {

        this.status = status;
    }

    public VerificationResult getVerificationResult() {

        return verificationResult;
    }

    public void setVerificationResult(VerificationResult verificationResult) {

        this.verificationResult = verificationResult;
    }

    public String getNonce() {

        return nonce;
    }

    public String getEphemeralPrivateKeyJwk() {

        return ephemeralPrivateKeyJwk;
    }

    public long getExpiresAt() {

        return expiresAt;
    }

    public String getClientId() {

        return clientId;
    }

    public String getClientIdScheme() {

        return clientIdScheme;
    }

    public String getResponseUri() {

        return responseUri;
    }

    public String getResponseMode() {

        return responseMode;
    }

    public String getWalletUrl() {

        return walletUrl;
    }

    public DcqlQuery getDcqlQuery() {

        return dcqlQuery;
    }

    public String getFailureReason() {

        return failureReason;
    }

    public void setFailureReason(String failureReason) {

        this.failureReason = failureReason;
    }

    /**
     * Builder for {@link VPFlowSession}.
     */
    public static class Builder {

        private String tenantDomain;
        private int tenantId;
        private VPFlowStatus status;
        private String nonce;
        private String ephemeralPrivateKeyJwk;
        private long expiresAt;
        private String clientId;
        private String clientIdScheme;
        private String responseUri;
        private String responseMode;
        private String walletUrl;
        private DcqlQuery dcqlQuery;

        public Builder tenantDomain(String tenantDomain) {

            this.tenantDomain = tenantDomain;
            return this;
        }

        public Builder tenantId(int tenantId) {

            this.tenantId = tenantId;
            return this;
        }

        public Builder status(VPFlowStatus status) {

            this.status = status;
            return this;
        }

        public Builder nonce(String nonce) {

            this.nonce = nonce;
            return this;
        }

        public Builder ephemeralPrivateKeyJwk(String ephemeralPrivateKeyJwk) {

            this.ephemeralPrivateKeyJwk = ephemeralPrivateKeyJwk;
            return this;
        }

        public Builder expiresAt(long expiresAt) {

            this.expiresAt = expiresAt;
            return this;
        }

        public Builder clientId(String clientId) {

            this.clientId = clientId;
            return this;
        }

        public Builder clientIdScheme(String clientIdScheme) {

            this.clientIdScheme = clientIdScheme;
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

        public Builder walletUrl(String walletUrl) {

            this.walletUrl = walletUrl;
            return this;
        }

        public Builder dcqlQuery(DcqlQuery dcqlQuery) {

            this.dcqlQuery = dcqlQuery;
            return this;
        }

        /**
         * Constructs a {@link VPFlowSession} from the values set on this builder.
         *
         * @return a new {@link VPFlowSession} instance
         */
        public VPFlowSession build() {

            VPFlowSession session = new VPFlowSession();
            session.tenantDomain = this.tenantDomain;
            session.tenantId = this.tenantId;
            session.status = this.status;
            session.nonce = this.nonce;
            session.ephemeralPrivateKeyJwk = this.ephemeralPrivateKeyJwk;
            session.expiresAt = this.expiresAt;
            session.clientId = this.clientId;
            session.clientIdScheme = this.clientIdScheme;
            session.responseUri = this.responseUri;
            session.responseMode = this.responseMode;
            session.walletUrl = this.walletUrl;
            session.dcqlQuery = this.dcqlQuery;
            return session;
        }
    }
}
