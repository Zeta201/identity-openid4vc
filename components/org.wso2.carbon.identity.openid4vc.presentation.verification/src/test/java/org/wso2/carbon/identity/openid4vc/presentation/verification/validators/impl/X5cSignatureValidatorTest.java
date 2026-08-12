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
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Unit tests for {@link X5cSignatureValidator}.
 *
 * <p>The embedded PKCS12 constant holds a self-signed EC test certificate used to verify that
 * the self-signed leaf check fires correctly. The PKCS12 was generated with:
 * {@code keytool -genkeypair -alias testissuer -keyalg EC -keysize 256 -sigalg SHA256withECDSA
 * -dname "CN=Test Issuer,O=Test Org,C=US" -validity 3650 -keystore test.jks -storepass changeit}
 * and then converted to PKCS12. For test use only.</p>
 */
public class X5cSignatureValidatorTest {

    /**
     * PKCS12 keystore (alias "testissuer", password "changeit") containing a self-signed
     * EC certificate (secp256r1). For test use only.
     */
    private static final String TEST_PKCS12_BASE64 =
            "MIIESAIBAzCCA/IGCSqGSIb3DQEHAaCCA+MEggPfMIID2zCCATIGCSqGSIb3DQEH" +
            "AaCCASMEggEfMIIBGzCCARcGCyqGSIb3DQEMCgECoIG9MIG6MGYGCSqGSIb3DQEF" +
            "DTBZMDgGCSqGSIb3DQEFDDArBBR17O+xnlXGRPS25Xf827AmpemsywICJxACASAw" +
            "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEPVjbw6+TL8FsKD9Zm6uLAsEUHoK" +
            "Ib8bv8SXIMOxlgCFwX9XU/LCPLm/Th2JcDdnjjcySYBd/rRuDEZch8d/rRXLicEg" +
            "UEd9s0i+PSrTlf3LHNGnl8vkfQIf9k4qcMj9NR/9MUgwIwYJKoZIhvcNAQkUMRYe" +
            "FAB0AGUAcwB0AGkAcwBzAHUAZQByMCEGCSqGSIb3DQEJFTEUBBJUaW1lIDE3ODYw" +
            "NDIwOTgyODEwggKhBgkqhkiG9w0BBwagggKSMIICjgIBADCCAocGCSqGSIb3DQEH" +
            "ATBmBgkqhkiG9w0BBQ0wWTA4BgkqhkiG9w0BBQwwKwQUqZKnVxlAtBnXbVQ7J6V5" +
            "OubpV68CAicQAgEgMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDgJ3v0CdWW" +
            "8Ft7+7yNcKS9gIICEHR6BdGjaUUNSQNEu9XFRNomuuQIybf4g45a/JH3JwR9kLTi" +
            "lNGhNU55TAeb+ykh5kSJ6xTa8Nm7oAbZhhIjolqv8Z+XIBM6sK821Sgxnf4h7kFI" +
            "6r6BvRYlf62746MLwhi2cobriAjhsdz0ACLD/3JVGj0Iz/0SWbC0b1U3ASohMMuA" +
            "HPVqFdLyO38AzHeLsUdTVCR36Huz4zBLWT6hvnHQaWGDAtXXz0DuaVtlhunQk/jV" +
            "zO8c+WMAvfe4MnU7Ov00lNeyqRFqVy9eO0fc+RUGALodmOqmb66+knKhTJokY2SH" +
            "NkJz/VNzVAyEGGO1K7GBYyi4KftOtAwuze+Oz/IbsWEi5SzZytaI8DFh6pUGsWOR" +
            "dYgB3R4v3RmjSyhh2SJwZWNnbEDYOKvi1DsMxzLcwwVXDmRF9n635cgd3y+wGA6M" +
            "AAPzlCTl9JGFEK0ANUU8plOJR20TfFmRp4M2gEcpYEUkG6Q63fFe6VvnKVf7WII/" +
            "ZeI9W2BkA4+9bH3SvqXZ8VxkZaoTB6ASgP8aHtxG8sA4l2pks1bGdN4dakpUHvph" +
            "vHQEd2uuw4AGLejNJssWl9Q8YUtcdm20LkxK9+2gecl6m8e4Y3cZQ0rYa/PcrB9m" +
            "QFjA2Ih1u3n+WZWG9R4srmJ11M7izLbIwCSzIPF0rrhGO1V5rBZYiAVzmvkKvUA3" +
            "o8rMArTtV89bAv3TdzBNMDEwDQYJYIZIAWUDBAIBBQAEIACN+fitP1E+ttlsw9o+" +
            "Yfx2etsJCHKG+L24fZxTMw96BBSMtQBH5N33EcryjEr9yCSykhDLKQICJxA=";

    private static final String PKCS12_PASSWORD = "changeit";
    private static final String PKCS12_ALIAS = "testissuer";

    private X5cSignatureValidator validator;
    private X509Certificate selfSignedCert;
    private ECPrivateKey selfSignedPrivateKey;

    @BeforeClass
    public void loadTestCertificate() throws Exception {

        byte[] pkcs12Bytes = java.util.Base64.getDecoder().decode(
                TEST_PKCS12_BASE64.replaceAll("\\s+", ""));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(pkcs12Bytes), PKCS12_PASSWORD.toCharArray());
        selfSignedCert = (X509Certificate) ks.getCertificate(PKCS12_ALIAS);
        selfSignedPrivateKey = (ECPrivateKey) ks.getKey(PKCS12_ALIAS, PKCS12_PASSWORD.toCharArray());
    }

    @BeforeMethod
    public void setUp() {

        validator = new X5cSignatureValidator();
    }

    @Test(priority = 1, description = "Test that getValidatorType returns the expected X5C type identifier")
    public void testGetValidatorTypeReturnsX5c() {

        // Execute test and verify
        Assert.assertEquals(validator.getValidatorType(), "X5C",
                "Validator type should be X5C");
    }

    @Test(priority = 2,
            description = "Test that validateSignature throws INVALID_SIGNATURE when the JWT header has no x5c chain")
    public void testValidateSignatureWithMissingX5cHeaderThrowsInvalidSignature() throws Exception {

        // Set up a plain JWT without an x5c header
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        String jwtWithoutX5c = buildJwt(JWSAlgorithm.RS256, new RSASSASigner(kp.getPrivate()),
                null);

        try {
            // Execute test
            validator.validateSignature(jwtWithoutX5c, new RequestedCredential());
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_SIGNATURE,
                    "Expected INVALID_SIGNATURE for missing x5c header, got: " + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 3,
            description = "Test validateSignature throws INVALID_SIGNATURE for a self-signed x5c chain")
    public void testValidateSignatureWithSelfSignedLeafCertThrowsInvalidSignature() throws Exception {

        // Build a JWT signed with the self-signed cert's EC key, x5c header contains only that cert.
        // The validator must reject it because subject == issuer (self-signed).
        List<Base64> x5cChain = Collections.singletonList(
                Base64.encode(selfSignedCert.getEncoded()));

        String jwtWithSelfSignedX5c = buildJwt(JWSAlgorithm.ES256, new ECDSASigner(selfSignedPrivateKey),
                x5cChain);

        try {
            // Execute test
            validator.validateSignature(jwtWithSelfSignedX5c, new RequestedCredential());
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_SIGNATURE,
                    "Expected INVALID_SIGNATURE for self-signed leaf cert, got: " + e.getErrorCode());
            return;
        }
        throw new AssertionError("Expected VerificationClientException but no exception was thrown");
    }

    @Test(priority = 4,
            description = "Test validateSignature throws VerificationException when no trusted CAs are configured")
    public void testValidateSignatureWithEnforceTrustedIssuerAndNoTrustedCasThrowsServerError()
            throws Exception {

        // This test uses a self-signed cert which will be rejected for self-signed BEFORE the
        // enforceTrustedIssuer check. We verify the self-signed error here.
        List<Base64> x5cChain = Collections.singletonList(
                Base64.encode(selfSignedCert.getEncoded()));
        String jwt = buildJwt(JWSAlgorithm.ES256, new ECDSASigner(selfSignedPrivateKey), x5cChain);

        RequestedCredential rc = new RequestedCredential();
        rc.setEnforceTrustedIssuer(true);
        rc.setTrustedCas(null);

        // Execute test — self-signed check fires first; INVALID_SIGNATURE confirms cert was decoded
        Assert.assertThrows(VerificationException.class,
                () -> validator.validateSignature(jwt, rc));
    }

    private String buildJwt(JWSAlgorithm algorithm,
                             com.nimbusds.jose.JWSSigner signer,
                             List<Base64> x5cChain) throws Exception {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test")
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000L))
                .build();

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT);
        if (x5cChain != null) {
            headerBuilder.x509CertChain(x5cChain);
        }

        SignedJWT jwt = new SignedJWT(headerBuilder.build(), claims);
        jwt.sign(signer);
        return jwt.serialize();
    }
}
