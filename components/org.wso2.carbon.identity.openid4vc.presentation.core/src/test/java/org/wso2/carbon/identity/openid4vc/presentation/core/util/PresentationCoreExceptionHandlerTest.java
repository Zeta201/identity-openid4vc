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
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;

/**
 * Unit tests for {@link PresentationCoreExceptionHandler}.
 */
public class PresentationCoreExceptionHandlerTest {

    @Test(priority = 1, description = "Test handleClientException populates all fields correctly")
    public void testHandleClientException() {

        PresentationCoreErrorCode errorCode = PresentationCoreErrorCode.INVALID_REQUEST;

        PresentationCoreClientException exception =
                PresentationCoreExceptionHandler.handleClientException(errorCode);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertEquals(exception.getCode(), errorCode.getCode(), "Code string should match");
        Assert.assertEquals(exception.getErrorType(), errorCode.getErrorType(), "Error type should match");
        Assert.assertEquals(exception.getMessage(), errorCode.getMessage(), "Message should match");
        Assert.assertEquals(exception.getDescription(), errorCode.getDescription(),
                "Description should match when no format args provided");
    }

    @Test(priority = 2, description = "Test handleClientException with format args interpolates description")
    public void testHandleClientExceptionWithFormatArgs() {

        PresentationCoreErrorCode errorCode = PresentationCoreErrorCode.PRESENTATION_DEFINITION_NOT_FOUND;
        String definitionId = "def-abc-123";

        PresentationCoreClientException exception =
                PresentationCoreExceptionHandler.handleClientException(errorCode, definitionId);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertTrue(exception.getDescription().contains(definitionId),
                "Description should contain the interpolated value");
        Assert.assertNull(exception.getCause(), "Client exception should have no cause");
    }

    @Test(priority = 3, description = "Test handleClientException returns PresentationCoreClientException type")
    public void testHandleClientExceptionType() {

        PresentationCoreClientException exception =
                PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.VP_REQUEST_EXPIRED);

        Assert.assertTrue(exception instanceof PresentationCoreClientException,
                "Should return a PresentationCoreClientException");
    }

    @Test(priority = 4, description = "Test handleServerException populates all fields and wraps cause")
    public void testHandleServerException() {

        PresentationCoreErrorCode errorCode = PresentationCoreErrorCode.INTERNAL_SERVER_ERROR;
        Throwable cause = new RuntimeException("underlying error");

        PresentationCoreServerException exception =
                PresentationCoreExceptionHandler.handleServerException(errorCode, cause);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertEquals(exception.getErrorCode(), errorCode, "Error code should match");
        Assert.assertEquals(exception.getCode(), errorCode.getCode(), "Code string should match");
        Assert.assertEquals(exception.getErrorType(), errorCode.getErrorType(), "Error type should match");
        Assert.assertEquals(exception.getMessage(), errorCode.getMessage(), "Message should match");
        Assert.assertEquals(exception.getDescription(), errorCode.getDescription(),
                "Description should match when no format args provided");
        Assert.assertEquals(exception.getCause(), cause, "Cause should be wrapped");
    }

    @Test(priority = 5, description = "Test handleServerException with null cause is accepted")
    public void testHandleServerExceptionNullCause() {

        PresentationCoreServerException exception =
                PresentationCoreExceptionHandler.handleServerException(
                        PresentationCoreErrorCode.SIGNING_ERROR, null);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertNull(exception.getCause(), "Null cause should not be wrapped");
    }

    @Test(priority = 6, description = "Test handleServerException with format args interpolates description")
    public void testHandleServerExceptionWithFormatArgs() {

        PresentationCoreErrorCode errorCode = PresentationCoreErrorCode.UNSUPPORTED_CLIENT_ID_SCHEME;
        String scheme = "x509_san_uri";

        PresentationCoreServerException exception =
                PresentationCoreExceptionHandler.handleServerException(errorCode, null, scheme);

        Assert.assertNotNull(exception, "Exception should not be null");
        Assert.assertTrue(exception.getDescription().contains(scheme),
                "Description should contain the interpolated scheme value");
    }

    @Test(priority = 7, description = "Test handleServerException returns PresentationCoreServerException type")
    public void testHandleServerExceptionType() {

        PresentationCoreServerException exception =
                PresentationCoreExceptionHandler.handleServerException(
                        PresentationCoreErrorCode.CONFIG_RETRIEVAL_ERROR, null);

        Assert.assertTrue(exception instanceof PresentationCoreServerException,
                "Should return a PresentationCoreServerException");
    }
}
