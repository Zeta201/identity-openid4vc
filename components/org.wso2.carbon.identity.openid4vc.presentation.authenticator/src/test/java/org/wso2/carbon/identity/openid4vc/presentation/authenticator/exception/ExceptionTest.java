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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Test class for VP authenticator exception types.
 * Tests message and error code behaviour across all exception variants.
 */
public class ExceptionTest {

    @DataProvider(name = "exceptionDataProvider")
    public Object[][] exceptionDataProvider() {

        return new Object[][]{
                {new VPAuthenticatorException("generic error")},
                {new VPAuthenticatorClientException("client error")},
                {new VPAuthenticatorServerException("server error")},
                {new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST, "invalid request")},
                {new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR, "internal error")}
        };
    }

    @Test(dataProvider = "exceptionDataProvider", priority = 1,
            description = "Test that all exception types return a non-null message")
    public void testExceptionMessage(VPAuthenticatorException exception) {

        Assert.assertNotNull(exception.getMessage(),
                "Exception message should not be null for any exception type");
    }

    @Test(priority = 2, description = "Test that a client exception preserves its error code and message")
    public void testExceptionWithErrorCode() {

        // Create exception with a specific error code
        VPAuthenticatorClientException ex = new VPAuthenticatorClientException(
                VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND, "not found");

        // Verify error code and message are preserved
        Assert.assertEquals(ex.getCode(), VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                "Exception error code should match the provided error code");
        Assert.assertEquals(ex.getMessage(), "not found",
                "Exception message should match the provided message");
    }
}
