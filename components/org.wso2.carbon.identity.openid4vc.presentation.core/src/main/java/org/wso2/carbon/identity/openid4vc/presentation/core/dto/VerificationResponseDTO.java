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

package org.wso2.carbon.identity.openid4vc.presentation.core.dto;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Outcome of verifying a credential presented in a VP submission.
 * Populated by the verification pipeline and stored on the
 * {@link org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession}
 * once the session transitions to {@code VERIFIED}. Fields are sourced directly
 * from the verified credential's JWT claims and key-binding proof.
 */
public class VerificationResponseDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Identifier of the credential definition that was requested and verified. */
    private String credentialId;
    /** Verifiable Credential Type ({@code vct}) claim from the SD-JWT VC. */
    private String vct;
    /** Credential format string (e.g. {@code dc+sd-jwt}) reported by the verifier. */
    private String credentialFormat;
    /** JWS algorithm used to sign the credential (e.g. {@code ES256}, {@code EdDSA}). */
    private String signingAlgorithm;
    /** {@code iss} claim from the credential; identifies the credential issuer. */
    private String issuer;
    /** {@code iat} claim from the credential; Unix timestamp (seconds) when the credential was issued. */
    private Long issuedAt;
    /** {@code exp} claim from the credential; Unix timestamp (seconds) after which the credential is invalid. */
    private Long expiresAt;
    /** Whether the key-binding JWT ({@code kb+jwt}) in the VP token was successfully verified. */
    private Boolean kbJwtVerified;
    /** Nonce extracted from the key-binding JWT; should match the nonce in the original request. */
    private String nonce;
    /** Unix timestamp (milliseconds) at which this server completed verification. */
    private Long verifiedAt;
    /** Subject claims extracted from the credential's disclosed payload, keyed by claim name. */
    private Map<String, Object> subjectClaims = new HashMap<>();

    public VerificationResponseDTO() {

    }

    public String getCredentialId() {

        return credentialId;
    }

    public void setCredentialId(String credentialId) {

        this.credentialId = credentialId;
    }

    public String getCredentialFormat() {

        return credentialFormat;
    }

    public void setCredentialFormat(String credentialFormat) {

        this.credentialFormat = credentialFormat;
    }

    public long getVerifiedAt() {

        return verifiedAt;
    }

    public void setVerifiedAt(long verifiedAt) {

        this.verifiedAt = verifiedAt;
    }

    public String getSigningAlgorithm() {

        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {

        this.signingAlgorithm = signingAlgorithm;
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

    public String getVct() {

        return vct;
    }

    public void setVct(String vct) {

        this.vct = vct;
    }

    public boolean isKbJwtVerified() {

        return kbJwtVerified;
    }

    public void setKbJwtVerified(boolean kbJwtVerified) {

        this.kbJwtVerified = kbJwtVerified;
    }

    public String getNonce() {

        return nonce;
    }

    public void setNonce(String nonce) {

        this.nonce = nonce;
    }

    public Map<String, Object> getSubjectClaims() {

        return new HashMap<>(subjectClaims);
    }

    public void setSubjectClaims(Map<String, Object> subjectClaims) {

        this.subjectClaims = subjectClaims != null ? new HashMap<>(subjectClaims) : new HashMap<>();
    }
}
