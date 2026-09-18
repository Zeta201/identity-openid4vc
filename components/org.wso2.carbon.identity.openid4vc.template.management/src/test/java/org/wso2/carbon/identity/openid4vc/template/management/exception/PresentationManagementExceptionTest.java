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

package org.wso2.carbon.identity.openid4vc.template.management.exception;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants.ErrorMessages;
import org.wso2.carbon.identity.openid4vc.template.management.util.PresentationDefinitionMgtExceptionHandler;

/**
 * Unit tests for the presentation management exception hierarchy and error messages.
 */
public class PresentationManagementExceptionTest {

    @Test(priority = 1,
            description = "Base exception with message only: errorCode and description are null")
    public void testBaseExceptionWithMessage() {

        PresentationManagementException ex = new PresentationManagementException("test message");

        Assert.assertEquals(ex.getMessage(), "test message");
        Assert.assertNull(ex.getErrorCode(), "errorCode should be null when constructed with message only");
        Assert.assertNull(ex.getDescription(), "description should be null when constructed with message only");
    }

    @Test(priority = 2,
            description = "Base exception with message and cause stores the cause")
    public void testBaseExceptionWithMessageAndCause() {

        RuntimeException cause = new RuntimeException("root cause");

        PresentationManagementException ex = new PresentationManagementException("test", cause);

        Assert.assertEquals(ex.getCause(), cause);
    }

    @Test(priority = 3,
            description = "Base exception with message, description, and error code stores all three fields")
    public void testBaseExceptionWithAllStringParams() {

        PresentationManagementException ex = new PresentationManagementException(
                "not found", "detailed description", "VPD-40401");

        Assert.assertEquals(ex.getMessage(), "not found");
        Assert.assertEquals(ex.getDescription(), "detailed description");
        Assert.assertEquals(ex.getErrorCode(), "VPD-40401");
    }

    @Test(priority = 4,
            description = "Base exception with all four params stores error code and cause")
    public void testBaseExceptionWithAllParams() {

        RuntimeException cause = new RuntimeException("cause");

        PresentationManagementException ex = new PresentationManagementException(
                "msg", "desc", "VPD-50001", cause);

        Assert.assertEquals(ex.getErrorCode(), "VPD-50001");
        Assert.assertEquals(ex.getDescription(), "desc");
        Assert.assertEquals(ex.getCause(), cause);
    }

    @Test(priority = 5,
            description = "Client exception extends the base exception")
    public void testClientExceptionIsInstanceOfBase() {

        PresentationManagementClientException ex =
                new PresentationManagementClientException("client error", "desc", "VPD-40001");

        Assert.assertTrue(ex instanceof PresentationManagementException);
    }

    @Test(priority = 6,
            description = "Client exception stores message, description, and error code")
    public void testClientExceptionStoredFields() {

        PresentationManagementClientException ex = new PresentationManagementClientException(
                "duplicate", "already exists", "VPD-40901");

        Assert.assertEquals(ex.getMessage(), "duplicate");
        Assert.assertEquals(ex.getDescription(), "already exists");
        Assert.assertEquals(ex.getErrorCode(), "VPD-40901");
    }

    @Test(priority = 7,
            description = "Server exception extends the base exception")
    public void testServerExceptionIsInstanceOfBase() {

        PresentationManagementServerException ex =
                new PresentationManagementServerException("server error");

        Assert.assertTrue(ex instanceof PresentationManagementException);
    }

    @Test(priority = 8,
            description = "Server exception with message and cause stores both")
    public void testServerExceptionWithMessageAndCause() {

        RuntimeException cause = new RuntimeException("cause");

        PresentationManagementServerException ex =
                new PresentationManagementServerException("db error", cause);

        Assert.assertEquals(ex.getMessage(), "db error");
        Assert.assertEquals(ex.getCause(), cause);
    }

    @Test(priority = 9,
            description = "Server exception with all four params stores error code and cause")
    public void testServerExceptionWithAllParams() {

        RuntimeException cause = new RuntimeException("cause");

        PresentationManagementServerException ex = new PresentationManagementServerException(
                "internal", "internal error desc", "VPD-50002", cause);

        Assert.assertEquals(ex.getErrorCode(), "VPD-50002");
        Assert.assertEquals(ex.getDescription(), "internal error desc");
        Assert.assertEquals(ex.getCause(), cause);
    }

    @DataProvider(name = "errorMessageProvider")
    public Object[][] errorMessageProvider() {

        return new Object[][]{
                {ErrorMessages.ERROR_CODE_VALIDATION_ERROR, "VPD-40001"},
                {ErrorMessages.ERROR_CODE_DEFINITION_NOT_FOUND, "VPD-40401"},
                {ErrorMessages.ERROR_CODE_DEFINITION_ALREADY_EXISTS, "VPD-40901"},
                {ErrorMessages.ERROR_CODE_DEFINITION_IN_USE, "VPD-40902"},
                {ErrorMessages.ERROR_CODE_INVALID_FILTER, "VPD-40002"},
                {ErrorMessages.ERROR_CODE_INVALID_PAGINATION, "VPD-40003"},
                {ErrorMessages.ERROR_CODE_DATABASE_ERROR, "VPD-50001"},
                {ErrorMessages.ERROR_CODE_INTERNAL_SERVER_ERROR, "VPD-50002"},
        };
    }

    @Test(dataProvider = "errorMessageProvider", priority = 10,
            description = "Each ErrorMessages entry has the expected code and non-null message and description")
    public void testErrorMessageValues(ErrorMessages error, String expectedCode) {

        Assert.assertEquals(error.getCode(), expectedCode,
                "Code should match for " + error);
        Assert.assertNotNull(error.getMessage(),
                "message should not be null for " + error);
        Assert.assertNotNull(error.getDescription(),
                "description should not be null for " + error);
    }

    @Test(priority = 11,
            description = "handleClientException produces client exception with correct code and formatted description")
    public void testHandleClientExceptionFormatsDescription() {

        PresentationManagementClientException ex = PresentationDefinitionMgtExceptionHandler
                .handleClientException(ErrorMessages.ERROR_CODE_DEFINITION_NOT_FOUND, "test-id");

        Assert.assertEquals(ex.getErrorCode(), ErrorMessages.ERROR_CODE_DEFINITION_NOT_FOUND.getCode());
        Assert.assertNotNull(ex.getMessage());
        Assert.assertTrue(ex.getDescription().contains("test-id"),
                "Description should contain the formatted data, got: " + ex.getDescription());
    }

    @Test(priority = 12,
            description = "handleServerException produces server exception with correct code and cause")
    public void testHandleServerExceptionStoresCause() {

        RuntimeException cause = new RuntimeException("db failure");

        PresentationManagementServerException ex = PresentationDefinitionMgtExceptionHandler
                .handleServerException(ErrorMessages.ERROR_CODE_DATABASE_ERROR, cause);

        Assert.assertEquals(ex.getErrorCode(), ErrorMessages.ERROR_CODE_DATABASE_ERROR.getCode());
        Assert.assertEquals(ex.getCause(), cause);
    }
}
