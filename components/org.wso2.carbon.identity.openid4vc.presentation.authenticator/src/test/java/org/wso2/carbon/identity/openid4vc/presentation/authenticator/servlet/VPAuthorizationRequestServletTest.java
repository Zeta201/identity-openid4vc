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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowInitiationResult;
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
 * Tests doGet and doPost via the public service(ServletRequest, ServletResponse) method.
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

    @Test(priority = 4,
            description = "Test doGet returns 200 with NOT_FOUND status when session is not found on the status path")
    public void testDoGetWhenSessionNotFoundOnStatusPath() throws Exception {

        // Set up status path request for a session that does not exist
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-missing/status");
        when(mockFlowService.getSession("req-missing")).thenReturn(null);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify 200 response with NOT_FOUND status in body
        verify(response).setStatus(HttpServletResponse.SC_OK);
        String body = responseOutput.getContent();
        Assert.assertTrue(body.contains("NOT_FOUND"),
                "Response body should contain status NOT_FOUND, got: " + body);
        Assert.assertTrue(body.contains("req-missing"),
                "Response body should contain the requestId, got: " + body);
    }

    @Test(priority = 5, description = "Test doGet returns 200 with VERIFIED status when session is verified")
    public void testDoGetWithVerifiedSession() throws Exception {

        // Set up a verified session
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-verified/status");
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-verified")
                .status(VPFlowStatus.VERIFIED)
                .build();
        when(mockFlowService.getSession("req-verified")).thenReturn(session);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_OK);
        Assert.assertTrue(responseOutput.getContent().contains("VERIFIED"),
                "Response body should contain status VERIFIED");
    }

    @Test(priority = 6,
            description = "Test doGet returns 200 with FAILED status and failure reason when session has failed")
    public void testDoGetWithFailedSession() throws Exception {

        // Set up a failed session with a failure reason
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-failed/status");
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-failed")
                .status(VPFlowStatus.FAILED)
                .build();
        session.setFailureReason("Credential signature invalid");
        when(mockFlowService.getSession("req-failed")).thenReturn(session);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_OK);
        String body = responseOutput.getContent();
        Assert.assertTrue(body.contains("FAILED"),
                "Response body should contain status FAILED");
        Assert.assertTrue(body.contains("Credential signature invalid"),
                "Response body should contain the failure reason");
    }

    @Test(priority = 7,
            description = "Test doGet returns EXPIRED status for an active session past its expiry time")
    public void testDoGetWithExpiredActiveSession() throws Exception {

        // Set up an active session with an expiry time well in the past
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-expired/status");
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-expired")
                .status(VPFlowStatus.ACTIVE)
                .expiresAt(1L)
                .build();
        when(mockFlowService.getSession("req-expired")).thenReturn(session);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_OK);
        Assert.assertTrue(responseOutput.getContent().contains("EXPIRED"),
                "Response body should contain status EXPIRED for an active session past its expiry");
    }

    @Test(priority = 8,
            description = "Test doGet returns ACTIVE status for a non-expired active session on the status path")
    public void testDoGetWithActiveSessionOnStatusPath() throws Exception {

        // Set up an active session that has not expired
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getPathInfo()).thenReturn("/req-active/status");
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-active")
                .status(VPFlowStatus.ACTIVE)
                .expiresAt(Long.MAX_VALUE)
                .build();
        when(mockFlowService.getSession("req-active")).thenReturn(session);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_OK);
        Assert.assertTrue(responseOutput.getContent().contains("ACTIVE"),
                "Response body should contain status ACTIVE");
    }

    @Test(priority = 9,
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

    @Test(priority = 10, description = "Test doPost returns 501 when the OpenID4VP feature is not enabled")
    public void testDoPostWhenFeatureNotEnabled() throws Exception {

        // Feature is disabled when VPFlowService is null
        VPDataHolder.setVPFlowService(null);
        when(request.getMethod()).thenReturn("POST");
        when(request.getPathInfo()).thenReturn("/req-abc/reinitiate");

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                "OpenID4VP feature is not enabled.");
    }

    @Test(priority = 11, description = "Test doPost reinitiate returns 200 with walletUrl and expiresAt on success")
    public void testDoPostReinitiateSuccess() throws Exception {

        // Set up reinitiation request
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getMethod()).thenReturn("POST");
        when(request.getPathInfo()).thenReturn("/req-old/reinitiate");
        VPFlowInitiationResult result = new VPFlowInitiationResult(
                "req-new", "openid4vp://wallet?request_uri=https://example.com",
                "https://example.com/request/req-new", null, 9999999999L);
        when(mockFlowService.reinitiate("req-old")).thenReturn(result);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_OK);
        String body = responseOutput.getContent();
        Assert.assertTrue(body.contains("walletUrl"),
                "Response body should contain walletUrl, got: " + body);
        Assert.assertTrue(body.contains("expiresAt"),
                "Response body should contain expiresAt, got: " + body);
    }

    @Test(priority = 12, description = "Test doPost reinitiate returns 404 when the session to reinitiate is not found")
    public void testDoPostReinitiateWhenSessionNotFound() throws Exception {

        // Set up reinitiation request for a non-existent session
        VPDataHolder.setVPFlowService(mockFlowService);
        when(request.getMethod()).thenReturn("POST");
        when(request.getPathInfo()).thenReturn("/req-missing/reinitiate");
        when(mockFlowService.reinitiate("req-missing")).thenThrow(
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                        "Session not found."));

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_NOT_FOUND);
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
