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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link VPAuthorizationRequestServlet}.
 * Tests doGet via the public service(ServletRequest, ServletResponse) method.
 */
public class VPAuthorizationRequestServletTest {

    private VPAuthorizationRequestServlet servlet;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private InMemoryServletOutputStream responseOutput;
    private VPFlowService mockFlowService;

    @BeforeMethod
    public void setUp() throws Exception {

        servlet = new VPAuthorizationRequestServlet();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        responseOutput = new InMemoryServletOutputStream();
        mockFlowService = mock(VPFlowService.class);
        when(request.getMethod()).thenReturn("GET");
        when(response.getOutputStream()).thenReturn(responseOutput);
    }

    @AfterMethod
    public void tearDown() {

        VPDataHolder.setVPFlowService(null);
    }

    @Test(priority = 1, description = "Test doGet returns 501 when the OpenID4VP feature is not enabled")
    public void testDoGetWhenFeatureNotEnabled() throws Exception {

        // Feature is disabled when VPFlowService is null
        VPDataHolder.setVPFlowService(null);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                "OpenID4VP feature is not enabled.");
    }

    @Test(priority = 2, description = "Test doGet returns 400 when the request path is blank")
    public void testDoGetWithBlankPath() throws Exception {

        // Set up request with no path info
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn(null);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("Request ID is required"),
                "Response body should contain 'Request ID is required'");
    }

    @Test(priority = 3, description = "Test doGet returns 404 when session is not found and path is non-status")
    public void testDoGetWhenSessionNotFoundOnNonStatusPath() throws Exception {

        // Set up request for a session that does not exist
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-missing");
        when(mockFlowService.getSession("req-missing")).thenReturn(null);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    @Test(priority = 4, description = "Test doGet returns 404 for any sub-path")
    public void testDoGetRejectsSubPaths() throws Exception {

        // Status polling is handled by VPFlowStatusServlet; this servlet only serves /{requestId}
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-abc/status");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    @Test(priority = 5,
            description = "Test doGet serves the authorization request JWT when path is non-status")
    public void testDoGetWithActiveSessionOnNonStatusPath() throws Exception {

        // Set up an active session and stub the JWT creation
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-jwt");
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-jwt")
                .status(VPFlowStatus.ACTIVE)
                .expiresAt(Long.MAX_VALUE)
                .build();
        when(mockFlowService.getSession("req-jwt")).thenReturn(session);
        when(mockFlowService.createAuthorizationRequestJwt("req-jwt")).thenReturn("test.signed.jwt");

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_OK);
        Assert.assertEquals(responseOutput.getContent(), "test.signed.jwt",
                "Response body should be the signed authorization request JWT");
    }

    private static class InMemoryServletOutputStream extends ServletOutputStream {

        private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        @Override
        public void write(int b) {

            baos.write(b);
        }

        public String getContent() {
            return baos.toString(StandardCharsets.UTF_8);
        }
    }
}
