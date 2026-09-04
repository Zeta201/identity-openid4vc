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

package org.wso2.carbon.identity.openid4vc.presentation.verification.dto;

import java.io.Serializable;

/**
 * Metadata extracted from a verified VP token for a single credential presentation.
 * Carries the issuer identity, credential validity window, holder-binding details, and KB-JWT outcome.
 */
public class PresentationMetadata implements Serializable {

    private static final long serialVersionUID = 1L;

    private String vpFormat;
    // Epoch milliseconds — when IS received the VP token.
    private long presentationTime;

    // Issuer-signed JWT fields.
    private String algorithm;
    private String issuer;
    private Long issuedAt;
    private Long expiresAt;
    private String credentialType;

    // Holder binding (cnf.jwk) fields.
    private String holderBindingMethod;
    private String holderKeyType;
    private String holderKeyCurve;

    // KB-JWT fields.
    private boolean kbJwtVerified;
    private Long kbJwtPresentedAt;
    private String kbJwtAudience;
    private String nonce;

    private PresentationMetadata(Builder builder) {

        this.vpFormat = builder.vpFormat;
        this.presentationTime = builder.presentationTime;
        this.algorithm = builder.algorithm;
        this.issuer = builder.issuer;
        this.issuedAt = builder.issuedAt;
        this.expiresAt = builder.expiresAt;
        this.credentialType = builder.credentialType;
        this.holderBindingMethod = builder.holderBindingMethod;
        this.holderKeyType = builder.holderKeyType;
        this.holderKeyCurve = builder.holderKeyCurve;
        this.kbJwtVerified = builder.kbJwtVerified;
        this.kbJwtPresentedAt = builder.kbJwtPresentedAt;
        this.kbJwtAudience = builder.kbJwtAudience;
        this.nonce = builder.nonce;
    }

    public String getVpFormat() {

        return vpFormat;
    }

    public long getPresentationTime() {

        return presentationTime;
    }

    public String getAlgorithm() {

        return algorithm;
    }

    public String getIssuer() {

        return issuer;
    }

    public Long getIssuedAt() {

        return issuedAt;
    }

    public Long getExpiresAt() {

        return expiresAt;
    }

    public String getCredentialType() {

        return credentialType;
    }

    public String getHolderBindingMethod() {

        return holderBindingMethod;
    }

    public String getHolderKeyType() {

        return holderKeyType;
    }

    public String getHolderKeyCurve() {

        return holderKeyCurve;
    }

    public boolean isKbJwtVerified() {

        return kbJwtVerified;
    }

    public Long getKbJwtPresentedAt() {

        return kbJwtPresentedAt;
    }

    public String getKbJwtAudience() {

        return kbJwtAudience;
    }

    public String getNonce() {

        return nonce;
    }

    /**
     * Builder for {@link PresentationMetadata}.
     */
    public static class Builder {

        private String vpFormat;
        private long presentationTime;
        private String algorithm;
        private String issuer;
        private Long issuedAt;
        private Long expiresAt;
        private String credentialType;
        private String holderBindingMethod;
        private String holderKeyType;
        private String holderKeyCurve;
        private boolean kbJwtVerified;
        private Long kbJwtPresentedAt;
        private String kbJwtAudience;
        private String nonce;

        public Builder vpFormat(String vpFormat) {

            this.vpFormat = vpFormat;
            return this;
        }

        public Builder presentationTime(long presentationTime) {

            this.presentationTime = presentationTime;
            return this;
        }

        public Builder algorithm(String algorithm) {

            this.algorithm = algorithm;
            return this;
        }

        public Builder issuer(String issuer) {

            this.issuer = issuer;
            return this;
        }

        public Builder issuedAt(Long issuedAt) {

            this.issuedAt = issuedAt;
            return this;
        }

        public Builder expiresAt(Long expiresAt) {

            this.expiresAt = expiresAt;
            return this;
        }

        public Builder credentialType(String credentialType) {

            this.credentialType = credentialType;
            return this;
        }

        public Builder holderBindingMethod(String holderBindingMethod) {

            this.holderBindingMethod = holderBindingMethod;
            return this;
        }

        public Builder holderKeyType(String holderKeyType) {

            this.holderKeyType = holderKeyType;
            return this;
        }

        public Builder holderKeyCurve(String holderKeyCurve) {

            this.holderKeyCurve = holderKeyCurve;
            return this;
        }

        public Builder kbJwtVerified(boolean kbJwtVerified) {

            this.kbJwtVerified = kbJwtVerified;
            return this;
        }

        public Builder kbJwtPresentedAt(Long kbJwtPresentedAt) {

            this.kbJwtPresentedAt = kbJwtPresentedAt;
            return this;
        }

        public Builder kbJwtAudience(String kbJwtAudience) {

            this.kbJwtAudience = kbJwtAudience;
            return this;
        }

        public Builder nonce(String nonce) {

            this.nonce = nonce;
            return this;
        }

        public PresentationMetadata build() {

            return new PresentationMetadata(this);
        }
    }
}
