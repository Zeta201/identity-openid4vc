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

package org.wso2.carbon.identity.openid4vc.presentation.verification.signature.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.SignatureValidationContext;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;

/**
 * Unit tests for {@link JwksValidator}.
 * Tests validator type and JWKS URI validation.
 */
public class JwksValidatorTest {

    private SignedJWT dummyJwt;
    private JwksValidator validator;

    @BeforeMethod
    public void setUp() throws Exception {

        validator = new JwksValidator();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("test").build();
        dummyJwt = new SignedJWT(header, claims);
        dummyJwt.sign(new ECDSASigner((ECPrivateKey) kp.getPrivate()));
    }

    @Test(priority = 1, description = "Test that getValidatorType returns the expected JWKS_URI type identifier")
    public void testGetValidatorTypeReturnsJwksUri() {

        // Execute test and verify
        Assert.assertEquals(validator.getValidatorType(), "JWKS_URI",
                "Validator type should be JWKS_URI");
    }

    @Test(priority = 2,
            description = "Test that validateSignature throws ISSUER_NOT_FOUND (server) when the JWKS URI is blank")
    public void testValidateSignatureWithBlankJwksUriThrowsIssuerNotFound() throws VerificationException {

        // Set up an issuer with a blank JWKS URI
        Issuer issuer = new Issuer();
        issuer.setJwksUri("   ");

        try {
            // Execute test
            validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer));
        } catch (VerificationServerException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.ISSUER_NOT_FOUND,
                    "Error code should be ISSUER_NOT_FOUND for a blank JWKS URI");
            return;
        }
        throw new AssertionError("Expected VerificationServerException but no exception was thrown");
    }

    @Test(priority = 3,
            description = "Test that validateSignature throws ISSUER_NOT_FOUND (server) when the JWKS URI is null")
    public void testValidateSignatureWithNullJwksUriThrowsIssuerNotFound() throws VerificationException {

        // Set up an issuer with a null JWKS URI (default)
        Issuer issuer = new Issuer();

        try {
            // Execute test
            validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer));
        } catch (VerificationServerException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.ISSUER_NOT_FOUND,
                    "Error code should be ISSUER_NOT_FOUND for a null JWKS URI");
            return;
        }
        throw new AssertionError("Expected VerificationServerException but no exception was thrown");
    }

    @Test(priority = 4,
            description = "Test validateSignature throws VerificationException when the JWKS URI uses plain HTTP")
    public void testValidateSignatureWithHttpJwksUriThrowsClientException() {

        // HttpClientUtil rejects plain HTTP — the error propagates as a VerificationClientException
        Issuer issuer = new Issuer();
        issuer.setJwksUri("http://example.com/.well-known/jwks.json");

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer)));
    }

    @Test(priority = 5,
            description = "Test validateSignature throws VerificationException when the JWKS URI is malformed")
    public void testValidateSignatureWithMalformedUrlThrowsClientException() {

        // Set up an issuer with a malformed JWKS URI
        Issuer issuer = new Issuer();
        issuer.setJwksUri("not-a-url-at-all");

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer)));
    }
}
