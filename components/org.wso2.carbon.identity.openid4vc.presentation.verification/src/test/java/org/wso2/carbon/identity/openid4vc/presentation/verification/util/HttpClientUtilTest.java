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

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

/**
 * Unit tests for {@link HttpClientUtil} SSRF protection and protocol enforcement.
 */
public class HttpClientUtilTest {

    @Test(priority = 1,
            description = "Test that fetchContent throws a VerificationClientException when a plain HTTP URL is used")
    public void testFetchContentWithHttpSchemeThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("http://example.com/jwks", null));
    }

    @Test(priority = 2,
            description = "Test that fetchContent returns INVALID_CREDENTIAL error code when a plain HTTP URL is used")
    public void testFetchContentWithHttpSchemeHasInvalidCredentialErrorCode() throws VerificationException {

        try {
            // Execute test
            HttpClientUtil.fetchContent("http://example.com/jwks", null);
        } catch (VerificationClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.INVALID_CREDENTIAL,
                    "Error code should be INVALID_CREDENTIAL for plain HTTP URLs");
        }
    }

    @Test(priority = 3,
            description = "Test that fetchContent throws a VerificationClientException when the URL has invalid syntax")
    public void testFetchContentWithInvalidUrlSyntaxThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("not-a-url", null));
    }

    @Test(priority = 4,
            description = "Test fetchContent throws VerificationClientException for loopback IPv4 to prevent SSRF")
    public void testFetchContentWithLoopbackIpv4ThrowsSsrfException() {

        // 127.0.0.1 is a loopback address — must be rejected before any network call
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("https://127.0.0.1/jwks", null));
    }

    @Test(priority = 5,
            description = "Test that fetchContent throws a VerificationClientException for localhost to prevent SSRF")
    public void testFetchContentWithLocalhostThrowsSsrfException() {

        // "localhost" resolves to the loopback address — must be rejected
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("https://localhost/jwks", null));
    }

    @Test(priority = 6,
            description = "Test fetchContent rejects 192.168.x.x private IP ranges to prevent SSRF")
    public void testFetchContentWithPrivateIpRange192ThrowsSsrfException() {

        // 192.168.x.x is a site-local (private) address
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("https://192.168.1.1/jwks", null));
    }

    @Test(priority = 7,
            description = "Test fetchContent rejects 10.x.x.x private IP ranges to prevent SSRF")
    public void testFetchContentWithPrivateIpRange10ThrowsSsrfException() {

        // 10.0.0.1 is a site-local (private) address
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("https://10.0.0.1/jwks", null));
    }

    @Test(priority = 8,
            description = "Test fetchContent rejects link-local addresses to prevent SSRF")
    public void testFetchContentWithLinkLocalAddressThrowsSsrfException() {

        // 169.254.x.x is a link-local address
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("https://169.254.1.1/jwks", null));
    }

    @Test(priority = 9,
            description = "Test fetchContent throws VerificationClientException when the host cannot be resolved")
    public void testFetchContentWithUnknownHostThrowsClientException() {

        // .invalid TLD is guaranteed to never resolve (RFC 2606)
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("https://this-host-does-not-exist.invalid/jwks", null));
    }

    @Test(priority = 10,
            description = "Test that fetchContent throws a VerificationClientException when the URL has invalid syntax")
    public void testFetchContentWithInvalidUrlThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("not-a-url", null));
    }

    @Test(priority = 11,
            description = "Test that HTTP scheme is rejected for openid-configuration URL")
    public void testFetchContentWithHttpSchemeForOpenIdConfigThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationClientException.class,
                () -> HttpClientUtil.fetchContent("http://example.com/openid-configuration", null));
    }
}
