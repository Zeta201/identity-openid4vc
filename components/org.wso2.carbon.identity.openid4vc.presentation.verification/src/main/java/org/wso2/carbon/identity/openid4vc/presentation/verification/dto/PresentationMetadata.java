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
import java.util.Map;

/**
 * DTO class for Presentation Metadata.
 * Carries everything extractable from the VP token in a structured form.
 */
public class PresentationMetadata implements Serializable {

    private static final long serialVersionUID = 1L;

    private String vpFormat;
    // epoch ms — when IS received the VP
    private long presentationTime;      

    // Issuer-signed JWT
    private String algorithm;           // JWT header alg (e.g. ES256)
    private String issuer;              // iss
    private Long issuedAt;              // iat epoch ms
    private Long expiresAt;             // exp epoch ms (null if absent)
    private String credentialType;      // vct

    // ── Holder binding (cnf.jwk)
    private String holderBindingMethod; // "cnf.jwk" if present
    private String holderKeyType;       // "EC" | "RSA" | "OKP"
    private String holderKeyCurve;      // "P-256", "Ed25519", etc. (null for RSA)

    // ── KB-JWT
    private boolean kbJwtVerified;
    private Long kbJwtPresentedAt;      // KB-JWT iat epoch ms
    private String kbJwtAudience;       // KB-JWT aud (the verifier)
    private String nonce;               // KB-JWT nonce (matches VP request nonce)

    // ── Credential claims
    /** Subject-attribute claims only — JWT/SD-JWT technical fields are excluded. */
    private Map<String, Object> credentialClaims;

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
        this.credentialClaims = builder.credentialClaims;
    }

    public String getVpFormat() {

        return vpFormat;
    }

    public void setVpFormat(String vpFormat) {

        this.vpFormat = vpFormat;
    }

    public long getPresentationTime() {

        return presentationTime;
    }

    public void setPresentationTime(long presentationTime) {

        this.presentationTime = presentationTime;
    }

    public String getAlgorithm() {

        return algorithm;
    }

    public void setAlgorithm(String algorithm) {

        this.algorithm = algorithm;
    }

    public String getIssuer() {

        return issuer;
    }

    public void setIssuer(String issuer) {

        this.issuer = issuer;
    }

    public Long getIssuedAt() {

        return issuedAt;
    }

    public void setIssuedAt(Long issuedAt) {

        this.issuedAt = issuedAt;
    }

    public Long getExpiresAt() {

        return expiresAt;
    }

    public void setExpiresAt(Long expiresAt) {

        this.expiresAt = expiresAt;
    }

    public String getCredentialType() {

        return credentialType;
    }

    public void setCredentialType(String credentialType) {

        this.credentialType = credentialType;
    }

    public String getHolderBindingMethod() {

        return holderBindingMethod;
    }

    public void setHolderBindingMethod(String holderBindingMethod) {

        this.holderBindingMethod = holderBindingMethod;
    }

    public String getHolderKeyType() {

        return holderKeyType;
    }

    public void setHolderKeyType(String holderKeyType) {

        this.holderKeyType = holderKeyType;
    }

    public String getHolderKeyCurve() {

        return holderKeyCurve;
    }

    public void setHolderKeyCurve(String holderKeyCurve) {

        this.holderKeyCurve = holderKeyCurve;
    }

    public boolean isKbJwtVerified() {

        return kbJwtVerified;
    }

    public void setKbJwtVerified(boolean kbJwtVerified) {

        this.kbJwtVerified = kbJwtVerified;
    }

    public Long getKbJwtPresentedAt() {

        return kbJwtPresentedAt;
    }

    public void setKbJwtPresentedAt(Long kbJwtPresentedAt) {

        this.kbJwtPresentedAt = kbJwtPresentedAt;
    }

    public String getKbJwtAudience() {

        return kbJwtAudience;
    }

    public void setKbJwtAudience(String kbJwtAudience) {

        this.kbJwtAudience = kbJwtAudience;
    }

    public String getNonce() {

        return nonce;
    }

    public void setNonce(String nonce) {

        this.nonce = nonce;
    }

    public Map<String, Object> getCredentialClaims() {

        return credentialClaims;
    }

    public void setCredentialClaims(Map<String, Object> credentialClaims) {

        this.credentialClaims = credentialClaims;
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
        private Map<String, Object> credentialClaims;

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

        public Builder credentialClaims(Map<String, Object> credentialClaims) {

            this.credentialClaims = credentialClaims;
            return this;
        }

        public PresentationMetadata build() {

            return new PresentationMetadata(this);
        }
    }
}
