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

import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;


/**
 * Input DTO passed to the credential verification pipeline.
 * Bundles the raw VP token from the wallet together with the expected values the verifier
 * must check to confirm the response was issued for this specific request.
 */
public class VerificationRequestDTO {

    /** Raw VP token (JWT or JSON-LD proof) submitted by the wallet. */
    private String token;
    /** Credential definition describing the expected credential type and schema. */
    private Credential credential;
    /** Nonce that was embedded in the original presentation request; must appear in the VP token. */
    private String expectedNonce;
    /** Audience value the wallet must address the VP token to; typically this server's client ID. */
    private String expectedAudience;

    public VerificationRequestDTO(String token, Credential credential,
            String expectedNonce, String expectedAudience) {

        this.token = token;
        this.credential = credential;
        this.expectedNonce = expectedNonce;
        this.expectedAudience = expectedAudience;
    }

    public String getToken() {

        return token;
    }

    public Credential getCredential() {

        return credential;
    }

    public String getExpectedNonce() {

        return expectedNonce;
    }

    public String getExpectedAudience() {

        return expectedAudience;
    }
}
