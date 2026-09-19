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

package org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.impl;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.internal.PresentationVerificationDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.SignatureValidationContext;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.KeyResolutionMethod;
import org.wso2.carbon.identity.sdjwt.SDJWT;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Unit tests for {@link SdJwtVcVerifier}.
 *
 * <p>Tests that require processing beyond SD-JWT parsing (expiry, vct, KB-JWT checks) stub
 * {@link PresentationVerificationDataHolder} via {@link MockedStatic} so that signature
 * validation passes without touching the real singleton or requiring a certificate chain.</p>
 */
public class SdJwtVcVerifierTest {

    private SdJwtVcVerifier sdJwtVcVerifier;
    private PrivateKey rsaPrivateKey;
    private MockedStatic<PresentationVerificationDataHolder> mockedHolder;
    private Credential baseCredential;

    @BeforeMethod
    public void setUp() throws Exception {

        sdJwtVcVerifier = new SdJwtVcVerifier();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        rsaPrivateKey = kp.getPrivate();

        // Build an X5C issuer config
        Issuer x5cIssuer = new Issuer();
        x5cIssuer.setKeyResolutionMethod(KeyResolutionMethod.X5C);

        baseCredential = new Credential();
        baseCredential.setIssuers(Collections.singletonList(x5cIssuer));

        // Stub the data holder so validateSignature() passes without touching the real singleton.
        CredentialSignatureValidator noOpValidator = new CredentialSignatureValidator() {

            @Override
            public String getValidatorType() {

                return CredentialSignatureValidator.TYPE_X5C;
            }

            @Override
            public void validateSignature(SignatureValidationContext context) throws VerificationException {
                // Intentional no-op: tests using this validator focus on post-signature logic.
            }
        };

        PresentationVerificationDataHolder mockHolderInstance =
                Mockito.mock(PresentationVerificationDataHolder.class);
        Mockito.when(mockHolderInstance.getCredentialSignatureValidator(CredentialSignatureValidator.TYPE_X5C))
               .thenReturn(Optional.of(noOpValidator));

        mockedHolder = Mockito.mockStatic(PresentationVerificationDataHolder.class);
        mockedHolder.when(PresentationVerificationDataHolder::getInstance).thenReturn(mockHolderInstance);
    }

    @AfterMethod
    public void tearDown() {

        if (mockedHolder != null) {
            mockedHolder.close();
        }
    }

    @Test(priority = 1, description = "Test that getFormat returns the DC_SD_JWT format identifier")
    public void testGetFormatReturnsDcSdJwt() {

        // Execute test and verify
        Assert.assertEquals(sdJwtVcVerifier.getFormat(), Constants.VC_SD_JWT_FORMAT,
                "getFormat should return the DC_SD_JWT format constant");
    }

    @Test(priority = 2,
            description = "Test verifyCredential throws INVALID_SD_JWT_FORMAT for a non-SD-JWT credential token")
    public void testVerifyCredentialWithInvalidSdJwtThrowsInvalidSdJwtFormat() throws VerificationException {

        // Set up a context with a malformed token
        VerificationRequestDTO ctx =
                new VerificationRequestDTO("invalid-sdjwt", baseCredential, null, null);

        try {
            // Execute test
            sdJwtVcVerifier.verifyCredential(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_SD_JWT_FORMAT,
                    "Error code should be INVALID_SD_JWT_FORMAT for an unparseable SD-JWT token");
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 3,
            description = "Test verifyCredential throws EXPIRED_CREDENTIAL when the expiry time is in the past")
    public void testVerifyCredentialWithExpiredCredentialThrowsExpiredCredential() throws Exception {

        // Set up a well-formed SD-JWT with an expiry time 1 hour in the past
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() - 3600_000L))
                .build();
        String sdJwtToken = buildMinimalSdJwt(claims);

        VerificationRequestDTO ctx = new VerificationRequestDTO(sdJwtToken, baseCredential, null, null);

        try {
            // Execute test
            sdJwtVcVerifier.verifyCredential(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.EXPIRED_CREDENTIAL,
                    "Expected EXPIRED_CREDENTIAL but got: " + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 4,
            description = "Test verifyCredential throws CREDENTIAL_TYPE_MISMATCH when vct doesn't match")
    public void testVerifyCredentialWithVctMismatchThrowsCredentialTypeMismatch() throws Exception {

        // verifyKeyBinding() unconditionally requires a KB-JWT, so the fixture must include a valid
        // one (matching cnf.jwk, sd_hash, and signature) to get past that gate and reach the vct check.
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);
        KeyPair holderKeyPair = ecKpg.generateKeyPair();
        ECKey holderPublicJwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) holderKeyPair.getPublic()).build();

        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", holderPublicJwk.toJSONObject());

        // Set up an SD-JWT with a vct that differs from the requested type
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .claim("vct", "https://example.com/credential-type-a")
                .claim("cnf", cnf)
                .build();
        String sdJwtToken = buildSdJwtWithKeyBinding(claims, holderKeyPair.getPrivate());

        Issuer x5cIssuer = new Issuer();
        x5cIssuer.setKeyResolutionMethod(KeyResolutionMethod.X5C);
        Credential rc = new Credential();
        rc.setIssuers(Collections.singletonList(x5cIssuer));
        rc.setType("https://example.com/credential-type-b");

        VerificationRequestDTO ctx = new VerificationRequestDTO(sdJwtToken, rc, null, null);

        try {
            // Execute test
            sdJwtVcVerifier.verifyCredential(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.CREDENTIAL_TYPE_MISMATCH,
                    "Expected CREDENTIAL_TYPE_MISMATCH for vct mismatch but got: " + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 5,
            description = "Test verifyCredential throws MISSING_KEY_BINDING_JWT when nonce expected, no KB-JWT")
    public void testVerifyCredentialWithNoKbJwtWhenNonceExpectedThrowsMissingKeyBindingJwt() throws Exception {

        // Set up a minimal SD-JWT (no KB-JWT) when the nonce is non-null
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .build();
        String sdJwtToken = buildMinimalSdJwt(claims);

        VerificationRequestDTO ctx =
                new VerificationRequestDTO(sdJwtToken, baseCredential, "expected-nonce-value", null);

        try {
            // Execute test
            sdJwtVcVerifier.verifyCredential(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.MISSING_KEY_BINDING_JWT,
                    "Expected MISSING_KEY_BINDING_JWT when nonce expected but no KB-JWT present, got: "
                            + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 6,
            description = "Test verifyCredential throws MISSING_KEY_BINDING_JWT when cnf present, no KB-JWT")
    public void testVerifyCredentialWithNoKbJwtWhenCnfPresentThrowsMissingKeyBindingJwt() throws Exception {

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

        VerificationRequestDTO ctx = new VerificationRequestDTO(sdJwtToken, baseCredential, null, null);

        try {
            // Execute test
            sdJwtVcVerifier.verifyCredential(ctx);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.MISSING_KEY_BINDING_JWT,
                    "Expected MISSING_KEY_BINDING_JWT when cnf present but no KB-JWT, got: "
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

    /**
     * Builds an SD-JWT presentation string with zero disclosures and a valid KB-JWT:
     * {@code <issuer-jwt>~<kb-jwt>}. The KB-JWT's {@code sd_hash} is computed the same way
     * {@code SdJwtVcVerifier} computes it, and it is signed with {@code holderPrivateKey}
     * (whose matching public key must be present as the issuer JWT's {@code cnf.jwk}) so that
     * {@code verifyKeyBinding()} accepts it and processing reaches the checks beyond it.
     */
    private String buildSdJwtWithKeyBinding(JWTClaimsSet claims, PrivateKey holderPrivateKey) throws Exception {

        SignedJWT issuerJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claims);
        issuerJwt.sign(new RSASSASigner(rsaPrivateKey));

        String presentationString = new SDJWT(issuerJwt.serialize(), Collections.emptyList()).serialize();
        byte[] sdHashBytes = MessageDigest.getInstance("SHA-256")
                .digest(presentationString.getBytes(StandardCharsets.US_ASCII));

        JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .claim("sd_hash", Base64URL.encode(sdHashBytes).toString())
                .build();
        SignedJWT kbJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                kbClaims);
        kbJwt.sign(new ECDSASigner((ECPrivateKey) holderPrivateKey));

        return presentationString + kbJwt.serialize();
    }
}
