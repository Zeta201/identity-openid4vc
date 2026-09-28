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

import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

/**
 * This interface validates a credential's cryptographic signature.
 */
public interface CredentialSignatureValidator {

    String TYPE_X5C = "X5C";
    String TYPE_JWKS_URI = "JWKS_URI";
    String TYPE_PEM = "PEM";

    /**
     * Returns the unique type key for this validator.
     *
     * @return Validator type key.
     */
    String getValidatorType();

    /**
     * Validates the cryptographic signature of the issuer-signed JWT in the given request.
     *
     * @param context Signature validation context.
     * @throws VerificationException If key resolution or signature verification fails.
     */
    void validateSignature(SignatureValidationContext context) throws VerificationException;
}
