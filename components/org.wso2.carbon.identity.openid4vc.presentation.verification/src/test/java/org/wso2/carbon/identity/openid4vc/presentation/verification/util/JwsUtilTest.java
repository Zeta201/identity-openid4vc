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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

/**
 * Unit tests for {@link JwsUtil}.
 * Tests RSA/EC signature verification, algorithm enforcement, and algorithm-switching attack prevention.
 */
public class JwsUtilTest {

    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;
    private PublicKey ecPublicKey;
    private PrivateKey ecPrivateKey;

    @BeforeMethod
    public void setUp() throws Exception {

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        KeyPair rsaKp = rsaKpg.generateKeyPair();
        rsaPublicKey = rsaKp.getPublic();
        rsaPrivateKey = rsaKp.getPrivate();

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);
        KeyPair ecKp = ecKpg.generateKeyPair();
        ecPublicKey = ecKp.getPublic();
        ecPrivateKey = ecKp.getPrivate();
    }

    @Test(priority = 1,
            description = "Test that verifySignatureWithPublicKey returns true for a valid RS256-signed JWT")
    public void testVerifySignatureWithRsaRS256Succeeds() throws Exception {

        // Set up a valid RS256-signed JWT
        SignedJWT jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256);

        // Execute test and verify
        Assert.assertTrue(JwsUtil.verifySignatureWithPublicKey(jwt, rsaPublicKey, "RS256"),
                "Signature verification should succeed for a valid RS256 JWT");
    }

    @Test(priority = 2,
            description = "Test verifySignatureWithPublicKey throws when algorithm does not match")
    public void testVerifySignatureWithAlgorithmMismatchThrowsVerificationException() throws Exception {

        // Set up — JWT is RS256 but caller claims RS384
        SignedJWT jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256);

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> JwsUtil.verifySignatureWithPublicKey(jwt, rsaPublicKey, "RS384"));
    }

    @Test(priority = 3,
            description = "Test that verifySignatureWithPublicKey returns true for a valid ES256-signed JWT")
    public void testVerifySignatureWithEcES256Succeeds() throws Exception {

        // Set up a valid ES256-signed JWT
        SignedJWT jwt = buildSignedJwtEc(ecPrivateKey, JWSAlgorithm.ES256);

        // Execute test and verify
        Assert.assertTrue(JwsUtil.verifySignatureWithPublicKey(jwt, ecPublicKey, "ES256"),
                "Signature verification should succeed for a valid ES256 JWT");
    }

    @Test(priority = 4,
            description = "Test verifySignatureWithPublicKey returns false/throws for the wrong EC public key")
    public void testVerifySignatureWithWrongPublicKeyReturnsFalseOrThrows() throws Exception {

        // Sign with ecPrivateKey but verify with a different EC key
        KeyPairGenerator ecKpg2 = KeyPairGenerator.getInstance("EC");
        ecKpg2.initialize(256);
        PublicKey differentEcPublicKey = ecKpg2.generateKeyPair().getPublic();

        SignedJWT jwt = buildSignedJwtEc(ecPrivateKey, JWSAlgorithm.ES256);

        try {
            // Execute test
            boolean result = JwsUtil.verifySignatureWithPublicKey(jwt, differentEcPublicKey, "ES256");

            // Returning false is also a valid outcome
            Assert.assertFalse(result,
                    "Expected signature verification to fail with a different public key");
        } catch (VerificationClientException e) {
            // Throwing INVALID_SIGNATURE is also acceptable
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_SIGNATURE,
                    "Error code should be INVALID_SIGNATURE when the wrong public key is used");
        }
    }

    @Test(priority = 5,
            description = "Test verifySignatureWithPublicKey throws UNSUPPORTED_SIGNING_ALGORITHM for 'none'")
    public void testVerifySignatureWithNoneAlgorithmThrowsClientException() throws Exception {

        // Set up a valid JWT
        SignedJWT jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256);

        try {
            // Execute test
            JwsUtil.verifySignatureWithPublicKey(jwt, rsaPublicKey, "none");
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.UNSUPPORTED_SIGNING_ALGORITHM,
                    "Expected UNSUPPORTED_SIGNING_ALGORITHM for 'none' algorithm");
            return;
        }
        throw new AssertionError("Expected VerificationClientException for 'none' algorithm");
    }

    @Test(priority = 6,
            description = "Test verifySignatureWithPublicKey throws UNSUPPORTED_SIGNING_ALGORITHM for a null algorithm")
    public void testVerifySignatureWithNullAlgorithmThrowsClientException() throws Exception {

        // Set up a valid JWT
        SignedJWT jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256);

        try {
            // Execute test
            JwsUtil.verifySignatureWithPublicKey(jwt, rsaPublicKey, null);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.UNSUPPORTED_SIGNING_ALGORITHM,
                    "Error code should be UNSUPPORTED_SIGNING_ALGORITHM for a null algorithm");
            return;
        }
        throw new AssertionError("Expected VerificationClientException for null algorithm");
    }

    @Test(priority = 7,
            description = "Test verifySignatureWithPublicKey throws UNSUPPORTED_SIGNING_ALGORITHM for HMAC")
    public void testVerifySignatureWithUnsupportedAlgorithmThrowsClientException() throws Exception {

        // Set up a valid JWT
        SignedJWT jwt = buildSignedJwt(rsaPrivateKey, JWSAlgorithm.RS256);

        try {
            // Execute test
            JwsUtil.verifySignatureWithPublicKey(jwt, rsaPublicKey, "HS256");
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.UNSUPPORTED_SIGNING_ALGORITHM,
                    "Expected UNSUPPORTED_SIGNING_ALGORITHM for disallowed algorithm HS256");
            return;
        }
        throw new AssertionError("Expected VerificationClientException for disallowed algorithm HS256");
    }

    private SignedJWT buildSignedJwt(PrivateKey privateKey, JWSAlgorithm algorithm) throws JOSEException {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("user-1")
                .issuer("https://issuer.example")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).build(),
                claims);
        jwt.sign(new RSASSASigner(privateKey));
        return jwt;
    }

    private SignedJWT buildSignedJwtEc(PrivateKey privateKey, JWSAlgorithm algorithm) throws Exception {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("user-1")
                .issuer("https://issuer.example")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).build(),
                claims);
        jwt.sign(new ECDSASigner((java.security.interfaces.ECPrivateKey) privateKey));
        return jwt;
    }
}
