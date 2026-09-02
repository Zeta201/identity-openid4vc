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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link VPAuthenticatorUtil}.
 * Tests subject identifier resolution, SAN DNS extraction, certificate hash computation,
 * and timeout resolution.
 */
public class VPAuthenticatorUtilTest {

    private static final long DEFAULT_TIMEOUT_MS = 120_000L;

    /**
     * Self-signed EC P-256 certificate (no SAN extension) for cert-parsing tests.
     * Alias "testissuer", password "changeit". Same key store used by
     * X5cSignatureValidatorTest in the verification module.
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

    private X509Certificate testCertNoSan;

    @BeforeClass
    public void loadTestCertificate() throws Exception {

        byte[] pkcs12Bytes = java.util.Base64.getDecoder().decode(
                TEST_PKCS12_BASE64.replaceAll("\\s+", ""));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(pkcs12Bytes), "changeit".toCharArray());
        testCertNoSan = (X509Certificate) ks.getCertificate("testissuer");
    }

    @Test(priority = 1, description = "Test resolveSubjectIdentifier returns namespaced ID when issuer is present")
    public void testResolveSubjectIdentifierWithIssuerAndMatchingClaim() {

        // Set up claims and metadata with an issuer
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "alice@example.com");
        PresentationMetadata metadata = new PresentationMetadata.Builder()
                .issuer("https://issuer.example.com")
                .build();

        // Execute test
        String result = VPAuthenticatorUtil.resolveSubjectIdentifier(claims, "email", metadata);

        // Verify
        Assert.assertEquals(result, "https://issuer.example.com#alice@example.com",
                "Result should be namespaced with issuer when issuer is present");
    }

    @Test(priority = 2, description = "Test resolveSubjectIdentifier returns raw claim value when metadata is null")
    public void testResolveSubjectIdentifierWithNullMetadata() {

        // Set up claims without metadata
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user-42");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveSubjectIdentifier(claims, "sub", null), "user-42",
                "Result should be the raw claim value when metadata is null");
    }

    @Test(priority = 3, description = "Test resolveSubjectIdentifier returns raw claim value when issuer is blank")
    public void testResolveSubjectIdentifierWithBlankIssuer() {

        // Set up claims and metadata with a blank issuer
        Map<String, Object> claims = Collections.singletonMap("sub", "user-42");
        PresentationMetadata metadata = new PresentationMetadata.Builder()
                .issuer("")
                .build();

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveSubjectIdentifier(claims, "sub", metadata), "user-42",
                "Result should be the raw claim value when issuer is blank");
    }

    @Test(priority = 4,
            description = "Test resolveSubjectIdentifier returns null when the subject claim is not in the map")
    public void testResolveSubjectIdentifierWithAbsentClaim() {

        // Set up claims that do not contain the subject claim name
        Map<String, Object> claims = Collections.singletonMap("email", "alice@example.com");

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.resolveSubjectIdentifier(claims, "sub", null),
                "Result should be null when the subject claim is absent from the claims map");
    }

    @Test(priority = 5, description = "Test resolveSubjectIdentifier returns null when subject claim name is null")
    public void testResolveSubjectIdentifierWithNullClaimName() {

        // Set up claims
        Map<String, Object> claims = Collections.singletonMap("sub", "user-42");

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.resolveSubjectIdentifier(claims, null, null),
                "Result should be null when subject claim name is null");
    }

    @Test(priority = 6, description = "Test resolveSubjectIdentifier returns null when subject claim name is blank")
    public void testResolveSubjectIdentifierWithBlankClaimName() {

        // Set up claims
        Map<String, Object> claims = Collections.singletonMap("sub", "user-42");

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.resolveSubjectIdentifier(claims, "   ", null),
                "Result should be null when subject claim name is blank");
    }

    @Test(priority = 7, description = "Test resolveSubjectIdentifier returns null when the claims map is empty")
    public void testResolveSubjectIdentifierWithEmptyClaims() {

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.resolveSubjectIdentifier(
                        Collections.emptyMap(), "email", null),
                "Result should be null when the claims map is empty");
    }

    @Test(priority = 8, description = "Test resolveSubjectClaimName returns null when IdP config is null")
    public void testResolveSubjectClaimNameWithNullConfig() {

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.resolveSubjectClaimName(null),
                "Result should be null when the IdP config is null");
    }

    @Test(priority = 9, description = "Test resolveSubjectClaimName returns null when claim config is null")
    public void testResolveSubjectClaimNameWithNullClaimConfig() {

        // Set up mock IdP config without a claim config
        ExternalIdPConfig mockConfig = mock(ExternalIdPConfig.class);
        IdentityProvider mockIdP = mock(IdentityProvider.class);
        when(mockConfig.getIdentityProvider()).thenReturn(mockIdP);
        when(mockIdP.getClaimConfig()).thenReturn(null);

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.resolveSubjectClaimName(mockConfig),
                "Result should be null when the claim config is null");
    }

    @Test(priority = 10, description = "Test resolveSubjectClaimName returns the user claim URI from the claim config")
    public void testResolveSubjectClaimNameWithValidUri() {

        // Set up mock IdP config with a user claim URI
        ExternalIdPConfig mockConfig = mock(ExternalIdPConfig.class);
        IdentityProvider mockIdP = mock(IdentityProvider.class);
        ClaimConfig mockClaimConfig = mock(ClaimConfig.class);
        when(mockConfig.getIdentityProvider()).thenReturn(mockIdP);
        when(mockIdP.getClaimConfig()).thenReturn(mockClaimConfig);
        when(mockClaimConfig.getUserClaimURI()).thenReturn("email");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveSubjectClaimName(mockConfig), "email",
                "Result should be the user claim URI from the claim config");
    }

    @Test(priority = 11, description = "Test extractSanDns returns null for a certificate without a SAN extension")
    public void testExtractSanDnsWithCertWithoutSan() {

        // Execute test and verify
        Assert.assertNull(VPAuthenticatorUtil.extractSanDns(testCertNoSan),
                "Result should be null for a certificate that has no dNSName SAN extension");
    }

    @Test(priority = 12, description = "Test computeCertHash returns a valid 43-character base64url SHA-256 hash")
    public void testComputeCertHash() throws Exception {

        // Execute test
        String hash = VPAuthenticatorUtil.computeCertHash(testCertNoSan);

        // Verify the hash is a 43-character base64url-encoded SHA-256 digest
        Assert.assertNotNull(hash, "Certificate hash should not be null");
        Assert.assertEquals(hash.length(), 43,
                "base64url(SHA-256(DER(cert))) without padding must be 43 characters");
        Assert.assertTrue(hash.matches("[A-Za-z0-9_-]+"),
                "Hash must contain only base64url characters");
    }

    @Test(priority = 13, description = "Test resolveTimeoutMs returns correct milliseconds for a valid timeout value")
    public void testResolveTimeoutMsWithValidValue() {

        // Set up properties with a valid timeout
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "120");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), 120_000L,
                "Valid timeout of 120 seconds should be converted to 120000 milliseconds");
    }

    @Test(priority = 14,
            description = "Test resolveTimeoutMs correctly parses a timeout value with surrounding whitespace")
    public void testResolveTimeoutMsWithWhitespace() {

        // Set up properties with whitespace-padded timeout
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "  60  ");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), 60_000L,
                "Timeout with surrounding whitespace should be parsed correctly");
    }

    @Test(priority = 15, description = "Test resolveTimeoutMs returns default when timeout is zero")
    public void testResolveTimeoutMsWithZero() {

        // Set up properties with zero timeout
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "0");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), DEFAULT_TIMEOUT_MS,
                "Zero is not a positive value and should fall back to the default timeout");
    }

    @Test(priority = 16, description = "Test resolveTimeoutMs returns default when timeout is negative")
    public void testResolveTimeoutMsWithNegativeValue() {

        // Set up properties with negative timeout
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "-10");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), DEFAULT_TIMEOUT_MS,
                "Negative value is not positive and should fall back to the default timeout");
    }

    @Test(priority = 17, description = "Test resolveTimeoutMs returns default when timeout value is non-numeric")
    public void testResolveTimeoutMsWithNonNumericValue() {

        // Set up properties with non-numeric timeout
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "two-minutes");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), DEFAULT_TIMEOUT_MS,
                "Non-numeric value should fall back to the default timeout");
    }

    @Test(priority = 18, description = "Test resolveTimeoutMs returns default when timeout value is blank")
    public void testResolveTimeoutMsWithBlankValue() {

        // Set up properties with blank timeout value
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "   ");

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), DEFAULT_TIMEOUT_MS,
                "Blank value should fall back to the default timeout");
    }

    @Test(priority = 19, description = "Test resolveTimeoutMs returns default when timeout key is absent from the map")
    public void testResolveTimeoutMsWithAbsentKey() {

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(Collections.emptyMap()), DEFAULT_TIMEOUT_MS,
                "Absent key should fall back to the default timeout");
    }

    @Test(priority = 20, description = "Test resolveTimeoutMs returns default when properties map is null")
    public void testResolveTimeoutMsWithNullProps() {

        // Execute test and verify
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(null), DEFAULT_TIMEOUT_MS,
                "Null properties map should fall back to the default timeout");
    }

    @Test(priority = 21, description = "Test resolveTimeoutMs returns default when timeout exceeds the maximum")
    public void testResolveTimeoutMsWithLargeValue() {

        // Set up properties with 1-hour timeout (exceeds max of 180s)
        Map<String, String> props = new HashMap<>();
        props.put(Constants.PROP_TIMEOUT_SECONDS, "3600");

        // Execute test and verify — out-of-range value falls back to default
        Assert.assertEquals(VPAuthenticatorUtil.resolveTimeoutMs(props), DEFAULT_TIMEOUT_MS,
                "Timeout exceeding the maximum should fall back to the default timeout");
    }
}
