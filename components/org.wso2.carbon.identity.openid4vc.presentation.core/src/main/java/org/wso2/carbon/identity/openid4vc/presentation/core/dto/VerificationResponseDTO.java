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
 * Outcome of verifying a single credential query within a VP presentation.
 */
public class VerificationResponseDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String credentialId;
    private String vct;
    private String credentialFormat;
    private String signingAlgorithm;
    private String issuer;
    private Long issuedAt;
    private Long expiresAt;
    private Boolean kbJwtVerified;
    private String nonce;
    private Long verifiedAt;
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
