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

package org.wso2.carbon.identity.openid4vc.presentation.management.exception;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit tests for the presentation management exception hierarchy and error codes.
 * Tests message, cause, error code, and error type behaviour across all exception variants.
 */
public class PresentationManagementExceptionTest {

    @Test(priority = 1,
        description = "Test that base exception stores the message and returns null error code by default")
    public void testBaseExceptionWithMessage() {

        // Set up and execute
        PresentationManagementException ex = new PresentationManagementException("test message");

        // Verify
        Assert.assertEquals(ex.getMessage(), "test message",
                "Exception message should match the value passed to the constructor");
        Assert.assertNull(ex.getErrorCode(),
                "errorCode should be null when constructed with message only");
        Assert.assertNull(ex.getCode(),
                "code should be null when constructed with message only");
    }

    @Test(priority = 2,
        description = "Test that base exception stores the cause when constructed with message and cause")
    public void testBaseExceptionWithMessageAndCause() {

        // Set up
        RuntimeException cause = new RuntimeException("root cause");

        // Execute
        PresentationManagementException ex = new PresentationManagementException("test", cause);

        // Verify
        Assert.assertEquals(ex.getCause(), cause,
                "Exception cause should match the RuntimeException passed to the constructor");
    }

    @Test(priority = 3,
        description = "Test that base exception stores error code, error type, and description")
    public void testBaseExceptionWithErrorCode() {

        // Execute
        PresentationManagementException ex = new PresentationManagementException(
                PresentationManagementErrorCode.DEFINITION_NOT_FOUND, "not found");

        // Verify
        Assert.assertEquals(ex.getCode(), PresentationManagementErrorCode.DEFINITION_NOT_FOUND.getCode(),
                "code should match the provided error code");
        Assert.assertEquals(ex.getErrorType(),
                PresentationManagementErrorCode.DEFINITION_NOT_FOUND.getErrorType(),
                "Error type should match the provided error code's error type value");
        Assert.assertNotNull(ex.getDescription(),
                "description should not be null when constructed with an error code");
    }

    @Test(priority = 4,
        description = "Test that PresentationManagementClientException is an instance of the base exception")
    public void testClientExceptionIsInstanceOfBase() {

        // Execute
        PresentationManagementClientException ex =
                new PresentationManagementClientException("client error");

        // Verify
        Assert.assertTrue(ex instanceof PresentationManagementException,
                "PresentationManagementClientException should extend PresentationManagementException");
    }

    @Test(priority = 5,
        description = "Test that client exception stores its error code and message correctly")
    public void testClientExceptionWithErrorCode() {

        // Execute
        PresentationManagementClientException ex = new PresentationManagementClientException(
                PresentationManagementErrorCode.VALIDATION_ERROR, "validation failed");

        // Verify
        Assert.assertEquals(ex.getCode(), PresentationManagementErrorCode.VALIDATION_ERROR.getCode(),
                "code should match the provided error code");
        Assert.assertEquals(ex.getMessage(), "validation failed",
                "message should match the value passed to the constructor");
    }

    @Test(priority = 6,
        description = "Test that client exception stores cause and error code when constructed with all three")
    public void testClientExceptionWithCause() {

        // Set up
        RuntimeException cause = new RuntimeException("cause");

        // Execute
        PresentationManagementClientException ex = new PresentationManagementClientException(
                PresentationManagementErrorCode.DEFINITION_ALREADY_EXISTS, "duplicate", cause);

        // Verify
        Assert.assertEquals(ex.getCause(), cause,
                "Exception cause should match the RuntimeException passed to the constructor");
        Assert.assertEquals(ex.getCode(), PresentationManagementErrorCode.DEFINITION_ALREADY_EXISTS.getCode(),
                "code should match the provided error code");
    }

    @Test(priority = 7,
        description = "Test that PresentationManagementServerException is an instance of the base exception")
    public void testServerExceptionIsInstanceOfBase() {

        // Execute
        PresentationManagementServerException ex =
                new PresentationManagementServerException("server error");

        // Verify
        Assert.assertTrue(ex instanceof PresentationManagementException,
                "PresentationManagementServerException should extend PresentationManagementException");
    }

    @Test(priority = 8,
        description = "Test that server exception stores its error code and message correctly")
    public void testServerExceptionWithErrorCode() {

        // Execute
        PresentationManagementServerException ex = new PresentationManagementServerException(
                PresentationManagementErrorCode.DATABASE_ERROR, "db error");

        // Verify
        Assert.assertEquals(ex.getCode(), PresentationManagementErrorCode.DATABASE_ERROR.getCode(),
                "code should match the provided error code");
        Assert.assertEquals(ex.getMessage(), "db error",
                "message should match the value passed to the constructor");
    }

    @Test(priority = 9,
            description = "Test that server exception stores cause and error code when constructed with all three")
    public void testServerExceptionWithCause() {

        // Set up
        RuntimeException cause = new RuntimeException("cause");

        // Execute
        PresentationManagementServerException ex = new PresentationManagementServerException(
                PresentationManagementErrorCode.INTERNAL_SERVER_ERROR, "internal", cause);

        // Verify
        Assert.assertEquals(ex.getCause(), cause,
                "Exception cause should match the RuntimeException passed to the constructor");
        Assert.assertEquals(ex.getCode(), PresentationManagementErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                "code should match the provided error code");
    }

    @DataProvider(name = "errorCodeProvider")
    public Object[][] errorCodeProvider() {

        return new Object[][]{
                {PresentationManagementErrorCode.VALIDATION_ERROR, "VPD-40001", "invalid_request"},
                {PresentationManagementErrorCode.DEFINITION_NOT_FOUND, "VPD-40401", "definition_not_found"},
                {PresentationManagementErrorCode.DEFINITION_ALREADY_EXISTS, "VPD-40901", "definition_already_exists"},
                {PresentationManagementErrorCode.DATABASE_ERROR, "VPD-50001", "server_error"},
                {PresentationManagementErrorCode.INTERNAL_SERVER_ERROR, "VPD-50002", "server_error"},
        };
    }

    @Test(dataProvider = "errorCodeProvider", priority = 10,
            description = "Test each error code has the expected code string, error type, message and description")
    public void testErrorCodeValues(PresentationManagementErrorCode code,
                                    String expectedCode, String expectedErrorType) {

        // Verify all fields are populated correctly for each error code
        Assert.assertEquals(code.getCode(), expectedCode,
                "Error code string should match for " + code);
        Assert.assertEquals(code.getErrorType(), expectedErrorType,
                "Error type should match for " + code);
        Assert.assertNotNull(code.getMessage(),
                "message should not be null for " + code);
        Assert.assertNotNull(code.getDescription(),
                "description should not be null for " + code);
    }

    @Test(priority = 11, description = "Test that toString on an error code includes the code string")
    public void testErrorCodeToString() {

        // Execute
        String str = PresentationManagementErrorCode.DEFINITION_NOT_FOUND.toString();

        // Verify
        Assert.assertTrue(str.contains("VPD-40401"),
                "toString should include the code string VPD-40401, got: " + str);
    }

    @Test(priority = 12,
            description = "Test that exception description is overridden when a custom description is provided")
    public void testExceptionDescriptionOverride() {

        // Execute
        PresentationManagementException ex = new PresentationManagementException(
                PresentationManagementErrorCode.VALIDATION_ERROR, "msg", "custom description");

        // Verify
        Assert.assertEquals(ex.getDescription(), "custom description",
                "getDescription should return the custom description passed to the constructor");
    }
}
