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

import com.nimbusds.jose.JOSEObjectType;
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
import java.util.Date;

/**
 * Unit tests for {@link PemValidator}.
 *
 * <p>The valid PEM constant is a self-signed EC certificate generated for test use only.
 * It is NOT used for any actual credential signing; it is only present so the PEM-parsing
 * code path can be exercised without needing a real issuer certificate.</p>
 */
public class PemValidatorTest {

    /**
     * A valid, non-expired self-signed EC certificate (secp256r1, SHA256withECDSA).
     * CN=Test Issuer, O=Test Org, C=US — valid 2026-2036. For test use only.
     */
    private static final String VALID_EC_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBhDCCASmgAwIBAgIIffEYiVeCQBUwCgYIKoZIzj0EAwIwNjELMAkGA1UEBhMC\n" +
            "VVMxETAPBgNVBAoTCFRlc3QgT3JnMRQwEgYDVQQDEwtUZXN0IElzc3VlcjAeFw0y\n" +
            "NjA4MDYxODQ3NTRaFw0zNjA4MDMxODQ3NTRaMDYxCzAJBgNVBAYTAlVTMREwDwYD\n" +
            "VQQKEwhUZXN0IE9yZzEUMBIGA1UEAxMLVGVzdCBJc3N1ZXIwWTATBgcqhkjOPQIB\n" +
            "BggqhkjOPQMBBwNCAAQacgWfuTKTIsyDCkC1FTcgtIvAju6RGCxSoKFgrr3gtV+K\n" +
            "nayOypBCGfIYXPBSU0fBWuGrLfgO3sp58XPP3G88oyEwHzAdBgNVHQ4EFgQUZXbC\n" +
            "/BkHHrmO+bgZU4lXYocZ+IowCgYIKoZIzj0EAwIDSQAwRgIhALyM2/98SI0YTGlN\n" +
            "+So9pdSmM4F/S3o+yo2vURLiLqCPAiEAmDKSmapPgYrmQCWPwizp/EpE1cTZuCSE\n" +
            "H+C3ysOktDg=\n" +
            "-----END CERTIFICATE-----";

    private SignedJWT dummyJwt;
    private PemValidator validator;

    @BeforeMethod
    public void setUp() throws Exception {

        validator = new PemValidator();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("test").build();
        dummyJwt = new SignedJWT(header, claims);
        dummyJwt.sign(new ECDSASigner(
                (java.security.interfaces.ECPrivateKey) kp.getPrivate()));
    }

    @Test(priority = 1, description = "Test that getValidatorType returns the expected PEM type identifier")
    public void testGetValidatorTypeReturnsPem() {

        // Execute test and verify
        Assert.assertEquals(validator.getValidatorType(), "PEM",
                "Validator type should be PEM");
    }

    @Test(priority = 2,
            description = "Test that validateSignature throws ISSUER_NOT_FOUND (server) when the PEM string is blank")
    public void testValidateSignatureWithBlankPemThrowsIssuerNotFound() throws VerificationException {

        // Set up an issuer with a blank PEM certificate
        Issuer issuer = new Issuer();
        issuer.setCertificate("   ");

        try {
            // Execute test
            validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer));
        } catch (VerificationServerException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.ISSUER_NOT_FOUND,
                    "Error code should be ISSUER_NOT_FOUND for a blank PEM string");
            return;
        }
        throw new AssertionError("Expected VerificationServerException but no exception was thrown");
    }

    @Test(priority = 3,
            description = "Test that validateSignature throws ISSUER_NOT_FOUND (server) when the PEM is null")
    public void testValidateSignatureWithNullPemThrowsIssuerNotFound() throws VerificationException {

        // Set up an issuer with a null PEM certificate (default)
        Issuer issuer = new Issuer();

        try {
            // Execute test
            validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer));
        } catch (VerificationServerException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.ISSUER_NOT_FOUND,
                    "Error code should be ISSUER_NOT_FOUND for a null PEM");
            return;
        }
        throw new AssertionError("Expected VerificationServerException but no exception was thrown");
    }

    @Test(priority = 4,
            description = "Test validateSignature throws VerificationException when the PEM is not a valid certificate")
    public void testValidateSignatureWithInvalidPemStringThrowsServerException() {

        // Set up an issuer with a non-certificate PEM string
        Issuer issuer = new Issuer();
        issuer.setCertificate("this is not a certificate");

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(new SignatureValidationContext(dummyJwt, issuer)));
    }

    @Test(priority = 5,
            description = "Test validateSignature throws INVALID_SIGNATURE for a JWT signed with a different key")
    public void testValidateSignatureWithValidPemButWrongKeyThrowsInvalidSignature() throws Exception {

        // Sign with a fresh EC key that does NOT correspond to VALID_EC_CERT_PEM's key.
        // Algorithm (ES256) matches the EC cert so parsing succeeds, but the signature
        // is made with a different key — PemValidator must reject it as INVALID_SIGNATURE.
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);
        KeyPair ecKp = ecKpg.generateKeyPair();
        ECDSASigner ecSigner = new ECDSASigner(
                (java.security.interfaces.ECPrivateKey) ecKp.getPrivate());
        JWSHeader ecHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .build();
        JWTClaimsSet ecClaims = new JWTClaimsSet.Builder()
                .subject("test-subject")
                .issueTime(new Date())
                .build();
        SignedJWT ecJwt = new SignedJWT(ecHeader, ecClaims);
        ecJwt.sign(ecSigner);

        Issuer issuer = new Issuer();
        issuer.setCertificate(VALID_EC_CERT_PEM);

        try {
            // Execute test
            validator.validateSignature(new SignatureValidationContext(ecJwt, issuer));
        } catch (VerificationException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_SIGNATURE,
                    "Expected INVALID_SIGNATURE when JWT key does not match PEM cert key, got: "
                            + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationException but no exception was thrown");
    }
}
