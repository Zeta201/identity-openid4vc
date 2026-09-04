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

/**
 * Carries everything a format-specific
 * {@link org.wso2.carbon.identity.openid4vc.presentation.verification.handlers.Verifier} needs to
 * verify a single credential presentation.
 */
public class CredentialVerificationContext {

    private final String credentialToken;
    private final DcqlQuery.CredentialQuery credentialQuery;
    private final int tenantId;
    private final String expectedNonce;
    private final String expectedAudience;

    public CredentialVerificationContext(String credentialToken, DcqlQuery.CredentialQuery credentialQuery,
                                         int tenantId, String expectedNonce, String expectedAudience) {

        this.credentialToken = credentialToken;
        this.credentialQuery = credentialQuery;
        this.tenantId = tenantId;
        this.expectedNonce = expectedNonce;
        this.expectedAudience = expectedAudience;
    }

    public String getCredentialToken() {

        return credentialToken;
    }

    public DcqlQuery.CredentialQuery getCredentialQuery() {

        return credentialQuery;
    }

    public int getTenantId() {

        return tenantId;
    }

    public String getExpectedNonce() {

        return expectedNonce;
    }

    public String getExpectedAudience() {

        return expectedAudience;
    }
}
