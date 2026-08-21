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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition.RequestedCredential;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

/**
 * Unit tests for {@link PemSignatureValidator}.
 *
 * <p>The valid PEM constant is a self-signed EC certificate generated for test use only.
 * It is NOT used for any actual credential signing; it is only present so the PEM-parsing
 * code path can be exercised without needing a real issuer certificate.</p>
 */
public class PemSignatureValidatorTest {

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

    private static final String PLACEHOLDER_JWT = "placeholder.jwt.token";

    private PemSignatureValidator validator;

    @BeforeMethod
    public void setUp() {

        validator = new PemSignatureValidator();
    }

    @Test(priority = 1, description = "Test that getValidatorType returns the expected PEM type identifier")
    public void testGetValidatorTypeReturnsPem() {

        // Execute test and verify
        Assert.assertEquals(validator.getValidatorType(), "PEM",
                "Validator type should be PEM");
    }

    @Test(priority = 2,
            description = "Test that validateSignature throws JWKS_RESOLUTION_ERROR when the PEM string is blank")
    public void testValidateSignatureWithBlankPemThrowsJwksResolutionError() throws VerificationException {

        // Set up a credential with a blank PEM
        RequestedCredential rc = new RequestedCredential();
        rc.setIssuerPem("   ");

        try {
            // Execute test
            validator.validateSignature(PLACEHOLDER_JWT, rc);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Error code should be JWKS_RESOLUTION_ERROR for a blank PEM string");
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 3, description = "Test that validateSignature throws JWKS_RESOLUTION_ERROR when the PEM is null")
    public void testValidateSignatureWithNullPemThrowsJwksResolutionError() throws VerificationException {

        // Set up a credential with a null PEM
        RequestedCredential rc = new RequestedCredential();
        rc.setIssuerPem(null);

        try {
            // Execute test
            validator.validateSignature(PLACEHOLDER_JWT, rc);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Error code should be JWKS_RESOLUTION_ERROR for a null PEM");
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 4,
            description = "Test validateSignature throws VerificationException when the PEM is not a valid certificate")
    public void testValidateSignatureWithInvalidPemStringThrowsServerException() {

        // Set up a credential with a non-certificate PEM string
        RequestedCredential rc = new RequestedCredential();
        rc.setIssuerPem("this is not a certificate");

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(PLACEHOLDER_JWT, rc));
    }

    @Test(priority = 5,
            description = "Test validateSignature throws INVALID_SIGNATURE for a JWT signed with a different key")
    public void testValidateSignatureWithValidPemButWrongKeyThrowsInvalidSignature() throws Exception {

        // Sign with a fresh EC key that does NOT correspond to VALID_EC_CERT_PEM's key.
        // Algorithm (ES256) matches the EC cert so parsing succeeds, but the signature
        // is made with a different key — SignatureVerifier must reject it as INVALID_SIGNATURE.
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
        String jwtSignedWithDifferentKey = ecJwt.serialize();

        RequestedCredential rc = new RequestedCredential();
        rc.setIssuerPem(VALID_EC_CERT_PEM);

        try {
            // Execute test
            validator.validateSignature(jwtSignedWithDifferentKey, rc);
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

