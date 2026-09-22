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

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link PresentationAuthenticator}.
 * Tests canHandle, getContextIdentifier, getName, and getFriendlyName.
 */
public class PresentationAuthenticatorTest {

    private PresentationAuthenticator authenticator;

    @BeforeMethod
    public void setUp() {

        authenticator = new PresentationAuthenticator();
    }

    @Test(priority = 1, description = "Test canHandle returns true when all required parameters are present")
    public void testCanHandleWithAllRequiredParams() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn("success");

        Assert.assertTrue(authenticator.canHandle(request),
                "canHandle should return true when all required params are present");
    }

    @Test(priority = 2, description = "Test canHandle returns false when status parameter is missing")
    public void testCanHandleWithMissingStatus() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn(null);

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when status is missing");
    }

    @Test(priority = 3, description = "Test canHandle returns false when sessionDataKey parameter is missing")
    public void testCanHandleWithMissingSessionDataKey() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn(null);
        when(request.getParameter("vp_request_id")).thenReturn("req-456");
        when(request.getParameter("status")).thenReturn("success");

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when sessionDataKey is missing");
    }

    @Test(priority = 4, description = "Test canHandle returns false when vp_request_id parameter is missing")
    public void testCanHandleWithMissingVpRequestId() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("key-123");
        when(request.getParameter("vp_request_id")).thenReturn(null);
        when(request.getParameter("status")).thenReturn("success");

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when vp_request_id is missing");
    }

    @Test(priority = 5, description = "Test canHandle returns false when all parameters are blank")
    public void testCanHandleWithAllBlankParams() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("   ");
        when(request.getParameter("vp_request_id")).thenReturn("   ");
        when(request.getParameter("status")).thenReturn("   ");

        Assert.assertFalse(authenticator.canHandle(request),
                "canHandle should return false when all params are blank");
    }

    @Test(priority = 6, description = "Test getContextIdentifier returns trimmed sessionDataKey value")
    public void testGetContextIdentifierWithSessionDataKey() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn("  ctx-789  ");

        String result = authenticator.getContextIdentifier(request);

        Assert.assertEquals(result, "ctx-789",
                "getContextIdentifier should return the trimmed session data key");
    }

    @Test(priority = 7, description = "Test getContextIdentifier returns null when sessionDataKey is null")
    public void testGetContextIdentifierWithNullKey() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sessionDataKey")).thenReturn(null);

        Assert.assertNull(authenticator.getContextIdentifier(request),
                "getContextIdentifier should return null when sessionDataKey is null");
    }

    @Test(priority = 8, description = "Test getName returns the authenticator name")
    public void testGetName() {

        Assert.assertEquals(authenticator.getName(), "PresentationAuthenticator",
                "getName should return PresentationAuthenticator");
    }

    @Test(priority = 9, description = "Test getFriendlyName returns the authenticator friendly name")
    public void testGetFriendlyName() {

        Assert.assertEquals(authenticator.getFriendlyName(), "Wallet (OpenID4VP)",
                "getFriendlyName should return Wallet (OpenID4VP)");
    }
}
