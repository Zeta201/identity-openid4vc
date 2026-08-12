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

package org.wso2.carbon.identity.openid4vc.presentation.verification.validators.impl;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.HttpClientUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.CredentialSignatureValidator;

/**
 * Resolves the issuer's public key from a JWKS endpoint URI configured on the credential.
 */
public class JwksUriSignatureValidator implements CredentialSignatureValidator {

    @Override
    public String getValidatorType() {

        return TYPE_JWKS_URI;
    }

    @Override
    public void validateSignature(String issuerJwt, RequestedCredential requestedCredential)
            throws VerificationException {

        String jwksUri = requestedCredential.getJwksUri();
        if (StringUtils.isBlank(jwksUri)) {
            throw new VerificationClientException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "JWKS URI validator requires a non-blank JWKS URI to be configured on the credential.");
        }
        String jwksJson;
        try {
            jwksJson = HttpClientUtil.fetchContent(jwksUri, null);
            if (StringUtils.isBlank(jwksJson)) {
                throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        "Empty response received from JWKS URI: " + jwksUri);
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Failed to fetch JWKS from URI: " + jwksUri + " — " + e.getMessage(), e);
        }
        SignatureVerifier.verifyCredentialSignature(issuerJwt, jwksJson);
    }
}
