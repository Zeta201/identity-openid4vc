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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link WalletSubmissionServlet}.
 * Tests doPost via the public service(ServletRequest, ServletResponse) method.
 */
public class WalletSubmissionServletTest {

    private WalletSubmissionServlet servlet;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private InMemoryServletOutputStream responseOutput;

    @BeforeMethod
    public void setUp() throws Exception {

        servlet = new WalletSubmissionServlet();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        responseOutput = new InMemoryServletOutputStream();
        when(request.getMethod()).thenReturn("POST");
        when(response.getOutputStream()).thenReturn(responseOutput);
    }

    @AfterMethod
    public void tearDown() {

        VPDataHolder.setVPFlowService(null);
        VPDataHolder.setVerificationService(null);
    }

    @Test(priority = 1, description = "Test doPost returns 501 when the OpenID4VP feature is not enabled")
    public void testDoPostWhenFeatureNotEnabled() throws Exception {

        // Feature is disabled when VPFlowService is null
        VPDataHolder.setVPFlowService(null);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                "OpenID4VP feature is not enabled.");
    }

    @Test(priority = 2, description = "Test doPost returns 413 when the request body exceeds the maximum allowed size")
    public void testDoPostWhenBodyTooLarge() throws Exception {

        // Set up a request body that exceeds MAX_BODY_BYTES (1024 * 1024)
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        when(request.getContentLength()).thenReturn(1024 * 1024 + 1);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                "Request body exceeds maximum allowed size.");
    }

    @Test(priority = 3,
            description = "Test doPost sets session to FAILED and returns 200 when wallet sends an error response")
    public void testDoPostWithWalletErrorResponse() throws Exception {

        // Set up request with wallet error
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        setupFormEncodedRequest();
        when(request.getParameter("state")).thenReturn("req-error-123");
        when(request.getParameter("error")).thenReturn("access_denied");
        when(request.getParameter("error_description")).thenReturn("User denied the request");

        // Set up session to be updated
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-error-123")
                .status(VPFlowStatus.ACTIVE)
                .build();

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("req-error-123")).thenReturn(session);

            // Execute test
            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            // Verify session is set to FAILED and success response is returned
            Assert.assertEquals(session.getStatus(), VPFlowStatus.FAILED,
                    "Session status must be FAILED after wallet sends an error response");
            verify(mockCache).put("req-error-123", session);
            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertEquals(responseOutput.getContent(), "{}",
                    "Response body should be empty JSON object on wallet error");
        }
    }

    @Test(priority = 4, description = "Test doPost returns 400 when the state parameter is missing")
    public void testDoPostWithMissingState() throws Exception {

        // Set up request without state
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        setupFormEncodedRequest();
        when(request.getParameter("vp_token")).thenReturn("{\"cred-1\":[\"token1\"]}");
        when(request.getParameter("state")).thenReturn(null);

        // Execute test
        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        // Verify
        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("Missing state parameter"),
                "Response body should contain 'Missing state parameter'");
    }

    @Test(priority = 5, description = "Test doPost returns 400 when the vp_token parameter is missing")
    public void testDoPostWithMissingVpToken() throws Exception {

        // Set up request without vp_token
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        setupFormEncodedRequest();
        when(request.getParameter("vp_token")).thenReturn(null);
        when(request.getParameter("state")).thenReturn("req-123");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("req-123")).thenReturn(null);

            // Execute test
            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            // Verify
            verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
            Assert.assertTrue(responseOutput.getContent().contains("Missing vp_token"),
                    "Response body should contain 'Missing vp_token'");
        }
    }

    @Test(priority = 6, description = "Test doPost returns 400 when no session is found for the given state")
    public void testDoPostWithSessionNotFound() throws Exception {

        // Set up request with a state that has no corresponding session
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        setupFormEncodedRequest();
        when(request.getParameter("vp_token")).thenReturn("{\"cred-1\":[\"token1\"]}");
        when(request.getParameter("state")).thenReturn("unknown-req");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("unknown-req")).thenReturn(null);

            // Execute test
            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            // Verify
            verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
            Assert.assertTrue(responseOutput.getContent().contains("Invalid state parameter"),
                    "Response body should contain 'Invalid state parameter'");
        }
    }

    @Test(priority = 7,
            description = "Test doPost returns 400 when response mode is direct_post.jwt but submission is unencrypted")
    public void testDoPostWithResponseModeMismatch() throws Exception {

        // Set up request with valid submission
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        setupFormEncodedRequest();
        when(request.getParameter("vp_token")).thenReturn("{\"cred-1\":[\"token1\"]}");
        when(request.getParameter("state")).thenReturn("req-mismatch");

        // Session expects direct_post.jwt but the submission is plain form data (unencrypted)
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-mismatch")
                .responseMode("direct_post.jwt")
                .status(VPFlowStatus.ACTIVE)
                .build();

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("req-mismatch")).thenReturn(session);

            // Execute test
            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            // Verify
            verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
            Assert.assertTrue(responseOutput.getContent().contains("Response mode mismatch"),
                    "Response body should contain 'Response mode mismatch'");
        }
    }

    @Test(priority = 8, description = "Test doPost returns 200 with empty body after successful VP verification")
    public void testDoPostVerificationSuccess() throws Exception {

        // Set up services and valid form submission
        VerificationService mockVerification = mock(VerificationService.class);
        VPDataHolder.setVPFlowService(mock(VPFlowService.class));
        VPDataHolder.setVerificationService(mockVerification);
        setupFormEncodedRequest();
        when(request.getParameter("vp_token")).thenReturn("{\"cred-1\":[\"token1\"]}");
        when(request.getParameter("state")).thenReturn("req-success");

        // Set up session and a successful verification result
        VPFlowSession session = new VPFlowSession.Builder()
                .requestId("req-success")
                .responseMode(Constants.RESPONSE_MODE_DIRECT_POST)
                .status(VPFlowStatus.ACTIVE)
                .expiresAt(Long.MAX_VALUE)
                .build();
        VerificationResult verifiedResult = new VerificationResult.Builder()
                .isVerified(true)
                .build();
        when(mockVerification.verify(
                Mockito.any(), Mockito.anyInt(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(verifiedResult);

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("req-success")).thenReturn(session);

            // Execute test
            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            // Verify session is VERIFIED and response is 200 with empty body
            Assert.assertEquals(session.getStatus(), VPFlowStatus.VERIFIED,
                    "Session status must be VERIFIED after successful verification");
            verify(mockCache).put("req-success", session);
            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertEquals(responseOutput.getContent(), "{}",
                    "Response body should be empty JSON object on success");
        }
    }

    /**
     * Helper method to configure the mock request as a form-urlencoded POST with no error.
     */
    private void setupFormEncodedRequest() {

        when(request.getContentLength()).thenReturn(200);
        when(request.getContentType()).thenReturn("application/x-www-form-urlencoded");
        when(request.getParameter("response")).thenReturn(null);
        when(request.getParameter("error")).thenReturn(null);
        when(request.getParameter("error_description")).thenReturn(null);
    }

}
