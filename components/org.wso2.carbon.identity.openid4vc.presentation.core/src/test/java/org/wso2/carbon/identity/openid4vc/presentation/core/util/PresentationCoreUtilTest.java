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

package org.wso2.carbon.identity.openid4vc.presentation.core.util;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PresentationCoreUtil}.
 */
public class PresentationCoreUtilTest {

    // -------------------------------------------------------------------------
    // flattenVpTokenMap
    // -------------------------------------------------------------------------

    @Test(priority = 1, description = "Test flattenVpTokenMap with List values takes first element")
    public void testFlattenVpTokenMapListValues() {

        Map<String, Object> rawMap = new HashMap<>();
        rawMap.put("credential_1", Arrays.asList("token-value-a", "token-value-b"));
        rawMap.put("credential_2", Collections.singletonList("token-only"));

        Map<String, String> result = PresentationCoreUtil.flattenVpTokenMap(rawMap);

        Assert.assertEquals(result.get("credential_1"), "token-value-a",
                "Should take the first element from a List");
        Assert.assertEquals(result.get("credential_2"), "token-only",
                "Should take the single element from a singleton List");
    }

    @Test(priority = 2, description = "Test flattenVpTokenMap with String values passes through as-is")
    public void testFlattenVpTokenMapStringValues() {

        Map<String, Object> rawMap = new HashMap<>();
        rawMap.put("cred_a", "direct-token-string");

        Map<String, String> result = PresentationCoreUtil.flattenVpTokenMap(rawMap);

        Assert.assertEquals(result.get("cred_a"), "direct-token-string",
                "String values should be passed through unchanged");
    }

    @Test(priority = 3, description = "Test flattenVpTokenMap with null value maps to null")
    public void testFlattenVpTokenMapNullValue() {

        Map<String, Object> rawMap = new HashMap<>();
        rawMap.put("cred_null", null);

        Map<String, String> result = PresentationCoreUtil.flattenVpTokenMap(rawMap);

        Assert.assertTrue(result.containsKey("cred_null"), "Key should be present");
        Assert.assertNull(result.get("cred_null"), "Null value should map to null");
    }

    @Test(priority = 4, description = "Test flattenVpTokenMap with empty List maps to null")
    public void testFlattenVpTokenMapEmptyList() {

        Map<String, Object> rawMap = new HashMap<>();
        rawMap.put("cred_empty", Collections.emptyList());

        Map<String, String> result = PresentationCoreUtil.flattenVpTokenMap(rawMap);

        Assert.assertNull(result.get("cred_empty"), "Empty list should map to null");
    }

    @Test(priority = 5, description = "Test flattenVpTokenMap with empty input returns empty map")
    public void testFlattenVpTokenMapEmpty() {

        Map<String, String> result = PresentationCoreUtil.flattenVpTokenMap(new HashMap<>());

        Assert.assertNotNull(result, "Result should not be null");
        Assert.assertTrue(result.isEmpty(), "Result should be empty for empty input");
    }

    @Test(priority = 6, description = "Test flattenVpTokenMap with mixed value types")
    public void testFlattenVpTokenMapMixedTypes() {

        Map<String, Object> rawMap = new HashMap<>();
        rawMap.put("list_cred", Arrays.asList("jwt.token.here"));
        rawMap.put("string_cred", "plain-jwt");
        rawMap.put("null_cred", null);

        Map<String, String> result = PresentationCoreUtil.flattenVpTokenMap(rawMap);

        Assert.assertEquals(result.size(), 3, "All entries should be present");
        Assert.assertEquals(result.get("list_cred"), "jwt.token.here");
        Assert.assertEquals(result.get("string_cred"), "plain-jwt");
        Assert.assertNull(result.get("null_cred"));
    }

    // -------------------------------------------------------------------------
    // extractSanDns
    // -------------------------------------------------------------------------

    @Test(priority = 7, description = "Test extractSanDns returns null when certificate has no SANs")
    public void testExtractSanDnsNoSan() throws CertificateParsingException {

        X509Certificate mockCert = mock(X509Certificate.class);
        when(mockCert.getSubjectAlternativeNames()).thenReturn(null);

        String result = PresentationCoreUtil.extractSanDns(mockCert);

        Assert.assertNull(result, "Should return null when certificate has no SAN extension");
    }

    @Test(priority = 8, description = "Test extractSanDns returns DNS name from SAN extension")
    public void testExtractSanDnsWithDnsName() throws CertificateParsingException {

        X509Certificate mockCert = mock(X509Certificate.class);
        Collection<List<?>> sans = new ArrayList<>();
        List<Object> dnsEntry = new ArrayList<>();
        dnsEntry.add(2); // dNSName general name type
        dnsEntry.add("localhost");
        sans.add(dnsEntry);
        when(mockCert.getSubjectAlternativeNames()).thenReturn(sans);

        String result = PresentationCoreUtil.extractSanDns(mockCert);

        Assert.assertEquals(result, "localhost", "Should extract DNS SAN value from certificate");
    }

    @Test(priority = 9, description = "Test extractSanDns skips non-DNS SAN types and returns null")
    public void testExtractSanDnsSkipsNonDnsTypes() throws CertificateParsingException {

        X509Certificate mockCert = mock(X509Certificate.class);
        Collection<List<?>> sans = new ArrayList<>();
        // Type 1 = rfc822Name (email), type 7 = iPAddress — neither should match
        List<Object> emailEntry = new ArrayList<>();
        emailEntry.add(1);
        emailEntry.add("admin@example.com");
        sans.add(emailEntry);
        when(mockCert.getSubjectAlternativeNames()).thenReturn(sans);

        String result = PresentationCoreUtil.extractSanDns(mockCert);

        Assert.assertNull(result, "Should return null when only non-DNS SAN types are present");
    }

    @Test(priority = 10, description = "Test extractSanDns returns first DNS name when multiple SANs present")
    public void testExtractSanDnsReturnsFirstDnsName() throws CertificateParsingException {

        X509Certificate mockCert = mock(X509Certificate.class);
        Collection<List<?>> sans = new ArrayList<>();
        List<Object> first = new ArrayList<>();
        first.add(2);
        first.add("primary.example.com");
        List<Object> second = new ArrayList<>();
        second.add(2);
        second.add("secondary.example.com");
        sans.add(first);
        sans.add(second);
        when(mockCert.getSubjectAlternativeNames()).thenReturn(sans);

        String result = PresentationCoreUtil.extractSanDns(mockCert);

        Assert.assertEquals(result, "primary.example.com",
                "Should return the first DNS SAN entry");
    }

    @Test(priority = 11, description = "Test extractSanDns returns null when CertificateParsingException is thrown")
    public void testExtractSanDnsParsingException() throws CertificateParsingException {

        X509Certificate mockCert = mock(X509Certificate.class);
        when(mockCert.getSubjectAlternativeNames())
                .thenThrow(new CertificateParsingException("malformed extension"));

        String result = PresentationCoreUtil.extractSanDns(mockCert);

        Assert.assertNull(result, "Should return null when certificate parsing fails");
    }
}
