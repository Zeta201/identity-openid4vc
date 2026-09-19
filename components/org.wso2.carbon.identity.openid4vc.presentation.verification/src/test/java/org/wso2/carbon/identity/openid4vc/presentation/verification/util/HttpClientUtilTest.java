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
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;

/**
 * Unit tests for {@link HttpClientUtil} protocol enforcement and URL validation.
 */
public class HttpClientUtilTest {

    @Test(priority = 1,
            description = "Test that fetchContent throws a VerificationException when a plain HTTP URL is used")
    public void testFetchContentWithHttpSchemeThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> HttpClientUtil.fetchContent("http://example.com/jwks"));
    }

    @Test(priority = 2,
            description = "Test that fetchContent returns ISSUER_NOT_FOUND error code when a plain HTTP URL is used")
    public void testFetchContentWithHttpSchemeHasIssuerNotFoundErrorCode() throws VerificationException {

        try {
            // Execute test
            HttpClientUtil.fetchContent("http://example.com/jwks");
        } catch (VerificationServerException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), VerificationErrorCode.ISSUER_NOT_FOUND,
                    "Error code should be ISSUER_NOT_FOUND for plain HTTP URLs");
        }
    }

    @Test(priority = 3,
            description = "Test that fetchContent throws a VerificationException when the URL has invalid syntax")
    public void testFetchContentWithInvalidUrlSyntaxThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> HttpClientUtil.fetchContent("not-a-url"));
    }

    @Test(priority = 4,
            description = "Test fetchContent throws VerificationException when the host cannot be resolved")
    public void testFetchContentWithUnknownHostThrowsClientException() {

        // .invalid TLD is guaranteed to never resolve (RFC 2606)
        Assert.assertThrows(VerificationException.class,
                () -> HttpClientUtil.fetchContent("https://this-host-does-not-exist.invalid/jwks"));
    }

    @Test(priority = 5,
            description = "Test that fetchContent throws a VerificationException when the URL has invalid syntax")
    public void testFetchContentWithInvalidUrlThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> HttpClientUtil.fetchContent("not-a-url"));
    }

    @Test(priority = 6,
            description = "Test that HTTP scheme is rejected for openid-configuration URL")
    public void testFetchContentWithHttpSchemeForOpenIdConfigThrowsClientException() {

        // Execute test and verify
        Assert.assertThrows(VerificationException.class,
                () -> HttpClientUtil.fetchContent("http://example.com/openid-configuration"));
    }
}
