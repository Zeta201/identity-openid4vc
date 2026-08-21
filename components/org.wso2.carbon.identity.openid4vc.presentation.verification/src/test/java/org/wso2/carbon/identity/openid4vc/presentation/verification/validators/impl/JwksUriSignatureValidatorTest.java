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

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.RequestedCredential;

/**
 * Unit tests for {@link JwksUriSignatureValidator}.
 * Tests validator type, JWKS URI validation, and SSRF protection.
 */
public class JwksUriSignatureValidatorTest {

    private static final String PLACEHOLDER_JWT = "placeholder.jwt.token";

    private JwksUriSignatureValidator validator;

    @BeforeMethod
    public void setUp() {

        validator = new JwksUriSignatureValidator();
    }

    @Test(priority = 1, description = "Test that getValidatorType returns the expected JWKS_URI type identifier")
    public void testGetValidatorTypeReturnsJwksUri() {

        // Execute test and verify
        Assert.assertEquals(validator.getValidatorType(), "JWKS_URI",
                "Validator type should be JWKS_URI");
    }

    @Test(priority = 2,
            description = "Test that validateSignature throws JWKS_RESOLUTION_ERROR when the JWKS URI is blank")
    public void testValidateSignatureWithBlankJwksUriThrowsJwksResolutionError() throws VerificationException {

        // Set up a credential with a blank JWKS URI
        RequestedCredential rc = new RequestedCredential();
        rc.setJwksUri("   ");

        try {
            // Execute test
            validator.validateSignature(PLACEHOLDER_JWT, rc);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Error code should be JWKS_RESOLUTION_ERROR for a blank JWKS URI");
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 3,
            description = "Test that validateSignature throws JWKS_RESOLUTION_ERROR when the JWKS URI is null")
    public void testValidateSignatureWithNullJwksUriThrowsJwksResolutionError() throws VerificationException {

        // Set up a credential with a null JWKS URI
        RequestedCredential rc = new RequestedCredential();
        rc.setJwksUri(null);

        try {
            // Execute test
            validator.validateSignature(PLACEHOLDER_JWT, rc);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Error code should be JWKS_RESOLUTION_ERROR for a null JWKS URI");
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 4,
            description = "Test validateSignature throws VerificationException when the JWKS URI uses plain HTTP")
    public void testValidateSignatureWithHttpJwksUriThrowsClientException() {

        // HttpClientUtil rejects plain HTTP — the error propagates as a VerificationClientException
        RequestedCredential rc = new RequestedCredential();
        rc.setJwksUri("http://example.com/.well-known/jwks.json");

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(PLACEHOLDER_JWT, rc));
    }

    @Test(priority = 5,
            description = "Test validateSignature throws VerificationException when the JWKS URI is malformed")
    public void testValidateSignatureWithMalformedUrlThrowsClientException() {

        // Set up a credential with a malformed JWKS URI
        RequestedCredential rc = new RequestedCredential();
        rc.setJwksUri("not-a-url-at-all");

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(PLACEHOLDER_JWT, rc));
    }

    @Test(priority = 6,
            description = "Test validateSignature throws VerificationClientException for a loopback JWKS URI")
    public void testValidateSignatureWithLoopbackJwksUriThrowsSsrfClientException() {

        // Set up a credential pointing to a loopback JWKS URI
        RequestedCredential rc = new RequestedCredential();
        rc.setJwksUri("https://127.0.0.1/.well-known/jwks.json");

        // Execute test and verify
        Assert.assertThrows(VerificationClientException.class,
                () -> validator.validateSignature(PLACEHOLDER_JWT, rc));
    }
}
