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

package org.wso2.carbon.identity.openid4vc.presentation.verification.signature;

import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;

/**
 * This class represents the context passed to a credential signature validator.
 */
public class SignatureValidationContext {

    private final SignedJWT issuerJwt;
    private final Issuer issuer;
    private String authenticatedSubject;

    public SignatureValidationContext(SignedJWT issuerJwt, Issuer issuer) {

        this.issuerJwt = issuerJwt;
        this.issuer = issuer;
    }

    public SignedJWT getIssuerJwt() {

        return issuerJwt;
    }

    public Issuer getIssuer() {

        return issuer;
    }

    /**
     * Returns the cryptographically authenticated issuer identity established during signature
     * validation, or {@code null} if the validator did not set one (in which case the caller should treat
     * the token's own {@code iss} claim as already authenticated, as is the case for jwks_uri/pem).
     *
     * @return The authenticated identity, or {@code null}.
     */
    public String getAuthenticatedSubject() {

        return authenticatedSubject;
    }

    /**
     * Records the cryptographically authenticated issuer identity established during signature
     * validation (e.g. a signing certificate's Subject DN for x5c), for use in place of the token's
     * self-asserted {@code iss} claim.
     *
     * @param authenticatedSubject The authenticated identity.
     */
    public void setAuthenticatedSubject(String authenticatedSubject) {

        this.authenticatedSubject = authenticatedSubject;
    }
}
