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

package org.wso2.carbon.identity.openid4vc.presentation.verification.handlers;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.internal.VerificationServiceComponentHolder;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.CredentialSignatureValidator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for {@link SdJwtVerifier}.
 *
 * <p>Tests that require processing beyond SD-JWT parsing (expiry, vct, KB-JWT checks) register a
 * no-op external validator in {@link VerificationServiceComponentHolder} so that signature
 * validation passes without a real cryptographic key or certificate chain.</p>
 */
public class SdJwtVerifierTest {

    private SdJwtVerifier sdJwtVerifier;
    private PrivateKey rsaPrivateKey;
    private CredentialSignatureValidator noOpValidator;

    @BeforeMethod
    public void setUp() throws Exception {

        sdJwtVerifier = new SdJwtVerifier();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        rsaPrivateKey = kp.getPrivate();

        // Register a passthrough validator so validateSignature() does not block further checks.
        noOpValidator = new CredentialSignatureValidator() {

            @Override
            public String getValidatorType() {

                return CredentialSignatureValidator.TYPE_X5C;
            }

            @Override
            public void validateSignature(String issuerJwt, RequestedCredential requestedCredential)
                    throws VerificationException {
                // Intentional no-op: tests using this validator focus on post-signature logic.
            }
        };
        VerificationServiceComponentHolder.getInstance().addExternalValidator(noOpValidator);
    }

    @AfterMethod
    public void tearDown() {

        VerificationServiceComponentHolder.getInstance().removeExternalValidator(noOpValidator);
    }

    @Test(priority = 1, description = "Test that getFormat returns the DC_SD_JWT format identifier")
    public void testGetFormatReturnsDcSdJwt() {

        // Execute test and verify
        Assert.assertEquals(sdJwtVerifier.getFormat(), Constants.VC_SD_JWT_FORMAT,
                "getFormat should return the DC_SD_JWT format constant");
    }

    @Test(priority = 2,
            description = "Test that verify throws PARSE_ERROR when the credential token is not a valid SD-JWT")
    public void testVerifyWithInvalidSdJwtThrowsParseError() throws VerificationException {

        // Set up a context with a malformed token
        CredentialVerificationContext ctx = new CredentialVerificationContext(
                "invalid-sdjwt", new RequestedCredential(), 1, null);

        try {
            // Execute test
            sdJwtVerifier.verify(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.PARSE_ERROR,
                    "Error code should be PARSE_ERROR for an unparseable SD-JWT token");
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 3, 
        description = "Test that verify throws EXPIRED_CREDENTIAL when the credential's expiry time is in the past")
    public void testVerifyWithExpiredCredentialThrowsExpiredCredential() throws Exception {

        // Set up a well-formed SD-JWT with an expiry time 1 hour in the past
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() - 3600_000L))
                .build();
        String sdJwtToken = buildMinimalSdJwt(claims);

        CredentialVerificationContext ctx = new CredentialVerificationContext(
                sdJwtToken, new RequestedCredential(), 1, null);

        try {
            // Execute test
            sdJwtVerifier.verify(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.EXPIRED_CREDENTIAL,
                    "Expected EXPIRED_CREDENTIAL but got: " + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 4, 
        description = "Test verify throws INVALID_CREDENTIAL when the vct claim does not match the requested type")
    public void testVerifyWithVctMismatchThrowsInvalidCredential() throws Exception {

        // Set up an SD-JWT with a vct that differs from the requested type
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .claim("vct", "https://example.com/credential-type-a")
                .build();
        String sdJwtToken = buildMinimalSdJwt(claims);

        RequestedCredential rc = new RequestedCredential();
        rc.setType("https://example.com/credential-type-b");

        CredentialVerificationContext ctx = new CredentialVerificationContext(
                sdJwtToken, rc, 1, null);

        try {
            // Execute test
            sdJwtVerifier.verify(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_CREDENTIAL,
                    "Expected INVALID_CREDENTIAL for vct mismatch but got: " + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 5, 
        description = "Test that verify throws INVALID_VP_FORMAT when a nonce is expected but no KB-JWT is present")
    public void testVerifyWithNoKbJwtWhenNonceExpectedThrowsInvalidVpFormat() throws Exception {

        // Set up a minimal SD-JWT (no KB-JWT) when the nonce is non-null
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .build();
        String sdJwtToken = buildMinimalSdJwt(claims);

        CredentialVerificationContext ctx = new CredentialVerificationContext(
                sdJwtToken, new RequestedCredential(), 1, "expected-nonce-value");

        try {
            // Execute test
            sdJwtVerifier.verify(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_VP_FORMAT,
                    "Expected INVALID_VP_FORMAT when nonce expected but no KB-JWT present, got: "
                            + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 6,
            description = "Test verify throws INVALID_VP_FORMAT when cnf is present but no KB-JWT is provided")
    public void testVerifyWithNoKbJwtWhenCnfPresentThrowsInvalidVpFormat() throws Exception {

        // Set up an SD-JWT with a cnf claim but without a KB-JWT
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", jwk);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .claim("cnf", cnf)
                .build();
        String sdJwtToken = buildMinimalSdJwt(claims);

        CredentialVerificationContext ctx = new CredentialVerificationContext(
                sdJwtToken, new RequestedCredential(), 1, null);

        try {
            // Execute test
            sdJwtVerifier.verify(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_VP_FORMAT,
                    "Expected INVALID_VP_FORMAT when cnf present but no KB-JWT, got: "
                            + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    /**
     * Builds a minimal SD-JWT presentation string: {@code <issuer-jwt>~}
     * (zero disclosures, no KB-JWT). The issuer JWT is signed with an RSA key;
     * the no-op validator registered in setUp() bypasses actual signature verification.
     */
    private String buildMinimalSdJwt(JWTClaimsSet claims) throws Exception {

        SignedJWT issuerJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claims);
        issuerJwt.sign(new RSASSASigner(rsaPrivateKey));
        return issuerJwt.serialize() + "~";
    }
}
