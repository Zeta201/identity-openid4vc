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

package org.wso2.carbon.identity.openid4vc.presentation.core.model;

import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.io.Serializable;

/**
 * Server-side state of a VP presentation flow, covering the full lifecycle from session
 * initiation through wallet response and verification outcome.
 *
 * <p>Instances are created via {@link Builder} when a presentation session starts and
 * are mutated in-place as the session progresses (status transitions, error recording,
 * verification result attachment). Serializable so entries can survive in a distributed cache.
 */
public class VPSession implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Unique session ID for this VP request; used as {@code state} in the presentation request. */
    private String requestId;
    /** Tenant domain that owns this session; used for tenant-scoped resource lookups. */
    private String tenantDomain;
    /** Numeric tenant ID corresponding to {@link #tenantDomain}; used as the cache partition key. */
    private int tenantId;
    /** Current lifecycle status of the session (ACTIVE, VERIFIED, or FAILED). */
    private VPSessionStatus status;
    /** Verification outcome stored once the session transitions to {@code VERIFIED}; null otherwise. */
    private VerificationResponseDTO verificationResponse;
    /** One-time nonce embedded in the presentation request; verified in the wallet's VP token. */
    private String nonce;
    /** Serialized ephemeral EC private key (JWK) used to decrypt a {@code direct_post.jwt} response. */
    private String ephemeralPrivateKeyJwk;
    /** Unix timestamp (milliseconds) after which this session is considered expired. */
    private long expiresAt;
    /** {@code client_id} sent in the presentation request; identifies this server to the wallet. */
    private String clientId;
    /** {@code client_id_scheme} agreed for this request (e.g. {@code x509_san_dns}, {@code redirect_uri}). */
    private String clientIdScheme;
    /** URI the wallet must POST the presentation response to ({@code response_uri}). */
    private String responseUri;
    /** Response mode agreed for this request ({@code direct_post} or {@code direct_post.jwt}). */
    private String responseMode;
    /** Deep-link URL handed to the wallet to initiate the presentation flow. */
    private String walletUrl;
    /** Presentation definition that specifies the credential(s) requested from the wallet. */
    private PresentationDefinition presentationDefinition;
    /** Machine-readable error type recorded when the session transitions to {@code FAILED}. */
    private String errorType;
    /** Human-readable error description recorded when the session transitions to {@code FAILED}. */
    private String errorDescription;

    public String getRequestId() {

        return requestId;
    }

    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public int getTenantId() {

        return tenantId;
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

    public PresentationDefinition getPresentationDefinition() {

        return presentationDefinition;
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

    public VPSession() {

    }

    /**
     * Builder for {@link VPSession}.
     */
    public static class Builder {

        private String requestId;
        private String tenantDomain;
        private int tenantId;
        private VPSessionStatus status;
        private String nonce;
        private String ephemeralPrivateKeyJwk;
        private long expiresAt;
        private String clientId;
        private String clientIdScheme;
        private String responseUri;
        private String responseMode;
        private String walletUrl;
        private PresentationDefinition presentationDefinition;

        public Builder requestId(String requestId) {

            this.requestId = requestId;
            return this;
        }

        public Builder tenantDomain(String tenantDomain) {

            this.tenantDomain = tenantDomain;
            return this;
        }

        public Builder tenantId(int tenantId) {

            this.tenantId = tenantId;
            return this;
        }

        public Builder status(VPSessionStatus status) {

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

        public Builder presentationDefinition(PresentationDefinition presentationDefinition) {

            this.presentationDefinition = presentationDefinition;
            return this;
        }

        /**
         * Constructs a {@link VPSession} from the values set on this builder.
         *
         * @return a new {@link VPSession} instance
         */
        public VPSession build() {

            VPSession session = new VPSession();
            session.requestId = this.requestId;
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
            session.presentationDefinition = this.presentationDefinition;
            return session;
        }
    }
}
