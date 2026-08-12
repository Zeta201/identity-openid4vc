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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link VPAuthenticator}.
 * Tests canHandle, getContextIdentifier, getName, getFriendlyName, and getConfigurationProperties.
 */
public class VPAuthenticatorTest {

    private VPAuthenticator authenticator;

    @BeforeMethod
    public void setUp() {

        authenticator = new VPAuthenticator();
    }

    @Test(priority = 1, description = "Test canHandle returns true when all required parameters are present")
    public void testCanHandleWithAllRequiredParams() {

        // Set up mock request
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn("success");

        // Execute test and verify
        Assert.assertTrue(authenticator.canHandle(request),
                "canHandle should return true when all required params are present");
    }

    @Test(priority = 2, description = "Test canHandle returns false when status parameter is missing")
    public void testCanHandleWithMissingStatus() {

        // Set up mock request without status
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn(null);

        // Execute test and verify
        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when status is missing");
    }

    @Test(priority = 3, description = "Test canHandle returns false when sessionDataKey parameter is missing")
    public void testCanHandleWithMissingSessionDataKey() {

        // Set up mock request without sessionDataKey
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn(null);
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn("success");

        // Execute test and verify
        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when sessionDataKey is missing");
    }

    @Test(priority = 4, description = "Test canHandle returns false when vp_request_id parameter is missing")
    public void testCanHandleWithMissingVpRequestId() {

        // Set up mock request without vp_request_id
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn(null);
        when(request.getParameter("status")).thenReturn("success");

        // Execute test and verify
        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when vp_request_id is missing");
    }

    @Test(priority = 5, description = "Test canHandle returns false when all parameters are blank")
    public void testCanHandleWithAllBlankParams() {

        // Set up mock request with blank values
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("   ");
        when(request.getParameter("vp_request_id")).thenReturn("   ");
        when(request.getParameter("status")).thenReturn("   ");

        // Execute test and verify
        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when all params are blank");
    }

    @Test(priority = 6, description = "Test getContextIdentifier returns trimmed sessionDataKey value")
    public void testGetContextIdentifierWithSessionDataKey() {

        // Set up mock request with padded sessionDataKey
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("  ctx-789  ");

        // Execute test
        String result = authenticator.getContextIdentifier(request);

        // Verify trimToNull is applied after encoding
        Assert.assertEquals(result, "ctx-789",
                "getContextIdentifier should return the trimmed session data key");
    }

    @Test(priority = 7, description = "Test getContextIdentifier returns null when sessionDataKey is null")
    public void testGetContextIdentifierWithNullKey() {

        // Set up mock request with null sessionDataKey
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn(null);

        // Execute test and verify
        Assert.assertNull(authenticator.getContextIdentifier(request),
                "getContextIdentifier should return null when sessionDataKey is null");
    }

    @Test(priority = 8, description = "Test getName returns the authenticator name constant")
    public void testGetName() {

        Assert.assertEquals(authenticator.getName(), Constants.AUTHENTICATOR_NAME,
                "getName should return the AUTHENTICATOR_NAME constant");
    }

    @Test(priority = 9, description = "Test getFriendlyName returns the authenticator friendly name constant")
    public void testGetFriendlyName() {

        Assert.assertEquals(authenticator.getFriendlyName(), Constants.AUTHENTICATOR_FRIENDLY_NAME,
                "getFriendlyName should return the AUTHENTICATOR_FRIENDLY_NAME constant");
    }

    @Test(priority = 10, description = "Test getConfigurationProperties returns exactly two properties")
    public void testGetConfigurationPropertiesCount() {

        // Execute test
        List<Property> properties = authenticator.getConfigurationProperties();

        // Verify
        Assert.assertEquals(properties.size(), 2,
                "getConfigurationProperties should return exactly 2 properties");
    }

    @Test(priority = 11,
            description = "Test getConfigurationProperties first property is the presentation definition ID")
    public void testGetConfigurationPropertiesFirstProperty() {

        // Execute test
        List<Property> properties = authenticator.getConfigurationProperties();

        // Verify
        Assert.assertEquals(properties.get(0).getName(), Constants.PROP_PRESENTATION_DEFINITION_ID,
                "First property should be the presentation definition ID property");
    }

    @Test(priority = 12, description = "Test getConfigurationProperties second property is the timeout")
    public void testGetConfigurationPropertiesSecondProperty() {

        // Execute test
        List<Property> properties = authenticator.getConfigurationProperties();

        // Verify
        Assert.assertEquals(properties.get(1).getName(), Constants.PROP_TIMEOUT_SECONDS,
                "Second property should be the timeout seconds property");
    }

    @Test(priority = 13, description = "Test getConfigurationProperties timeout property has the correct default value")
    public void testGetConfigurationPropertiesTimeoutDefaultValue() {

        // Execute test
        List<Property> properties = authenticator.getConfigurationProperties();
        Property timeoutProperty = properties.get(1);

        // Verify
        Assert.assertEquals(timeoutProperty.getDefaultValue(), Constants.PROP_TIMEOUT_DEFAULT_VALUE,
                "Timeout property should have the correct default value");
    }
}
