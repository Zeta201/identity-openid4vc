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
 * Immutable context DTO produced by
 * {@link org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationSessionService#buildVerificationRequest}
 * and consumed by the verification pipeline.
 *
 * <p>Each field is required by at least one verification step:
 * <ul>
 *   <li>{@code token} — the raw credential string (e.g. the compact SD-JWT) extracted from the
 *       vp_token map by credential query ID, handed to the verifier for parsing and signature
 *       validation.</li>
 *   <li>{@code credential} — the credential entry from the presentation definition, carrying the
 *       expected {@code vct}, format, and trusted issuer configurations used to select the correct
 *       signature validator and enforce type constraints.</li>
 *   <li>{@code expectedNonce} — the nonce issued by IS for this VP session; the verifier checks it
 *       matches the {@code nonce} claim in the KB-JWT to prevent replay attacks.</li>
 *   <li>{@code expectedAudience} — the verifier's {@code client_id} from the VP request; the
 *       verifier checks it appears in the KB-JWT {@code aud} claim.</li>
 * </ul>
 */
public class VerificationRequestDTO {

    private final String token;
    private final Credential credential;
    private final String expectedNonce;
    private final String expectedAudience;

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
