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

package org.wso2.carbon.identity.openid4vc.presentation.verification.validators;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

/**
 * Extension point for credential signature validation.
 *
 * <p>Built-in implementations:
 * <ul>
 *   <li>{@code X5C} — verifies against the x5c certificate chain embedded in the JOSE header (HAIP §6.1.1).</li>
 *   <li>{@code JWKS_URI} — fetches JWKS directly from a configured endpoint URI.</li>
 *   <li>{@code PEM} — derives the JWKS from a PEM-encoded certificate on the credential config.</li>
 * </ul>
 *
 * <p>To register a custom validator, implement this interface and publish it as an OSGi service.
 */
public interface CredentialSignatureValidator {

    String TYPE_X5C = "X5C";
    String TYPE_JWKS_URI = "JWKS_URI";
    String TYPE_PEM = "PEM";

    /**
     * Returns the unique type key for this validator (e.g. {@code "JWKS_URI"}).
     * This value is persisted in the database and used for look-up at verification time.
     */
    String getValidatorType();

    /**
     * Validates the cryptographic signature of the given issuer-signed JWT.
     *
     * @param issuerJwt    the raw SD-JWT VC issuer-signed JWT (compact serialisation)
     * @param issuerConfig the matched issuer configuration carrying key-resolution data
     *                     (JWKS URI, PEM certificate, or trusted CA cert for x5c)
     * @throws VerificationException if key resolution or signature verification fails
     */
    void validateSignature(String issuerJwt, DcqlQuery.IssuerConfig issuerConfig) throws VerificationException;
}
