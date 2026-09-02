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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link VPFlowStatusServlet}.
 * Verifies requestId-based session status polling.
 */
public class VPFlowStatusServletTest {

    private VPFlowStatusServlet servlet;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private InMemoryServletOutputStream responseOutput;

    @BeforeMethod
    public void setUp() throws Exception {

        servlet = new VPFlowStatusServlet();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        responseOutput = new InMemoryServletOutputStream();
        when(request.getMethod()).thenReturn("GET");
        when(response.getOutputStream()).thenReturn(responseOutput);
    }

    @Test(priority = 1, description = "Test doGet returns 400 when requestId parameter is absent")
    public void testDoGetMissingRequestId() throws Exception {

        when(request.getParameter("requestId")).thenReturn(null);

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("requestId"),
                "Response body should reference the missing requestId parameter");
    }

    @Test(priority = 2, description = "Test doGet returns 400 when requestId parameter is blank")
    public void testDoGetBlankRequestId() throws Exception {

        when(request.getParameter("requestId")).thenReturn("   ");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("invalid_request"),
                "Response body should contain error code invalid_request");
    }

    @Test(priority = 3, description = "Test doGet returns 200 NOT_FOUND when requestId is not in the cache")
    public void testDoGetRequestIdNotInCache() throws Exception {

        when(request.getParameter("requestId")).thenReturn("unknown-request-id");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("unknown-request-id")).thenReturn(null);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertTrue(responseOutput.getContent().contains("NOT_FOUND"),
                    "Response body should contain NOT_FOUND status when requestId resolves to no session");
        }
    }

    @Test(priority = 4, description = "Test doGet returns 200 ACTIVE for an active session")
    public void testDoGetActiveSession() throws Exception {

        when(request.getParameter("requestId")).thenReturn("req-active");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            VPFlowSession session = new VPFlowSession.Builder()
                    .requestId("req-active")
                    .status(VPFlowStatus.ACTIVE)
                    .build();
            when(mockCache.get("req-active")).thenReturn(session);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertTrue(responseOutput.getContent().contains("ACTIVE"),
                    "Response body should contain ACTIVE status");
        }
    }

    @Test(priority = 5, description = "Test doGet returns 200 VERIFIED for a verified session")
    public void testDoGetVerifiedSession() throws Exception {

        when(request.getParameter("requestId")).thenReturn("req-verified");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            VPFlowSession session = new VPFlowSession.Builder()
                    .requestId("req-verified")
                    .status(VPFlowStatus.VERIFIED)
                    .build();
            when(mockCache.get("req-verified")).thenReturn(session);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertTrue(responseOutput.getContent().contains("VERIFIED"),
                    "Response body should contain VERIFIED status");
        }
    }

    @Test(priority = 6, description = "Test doGet returns 200 FAILED with failure reason for a failed session")
    public void testDoGetFailedSession() throws Exception {

        when(request.getParameter("requestId")).thenReturn("req-failed");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            VPFlowSession session = new VPFlowSession.Builder()
                    .requestId("req-failed")
                    .status(VPFlowStatus.FAILED)
                    .build();
            session.setFailureReason("Credential signature invalid");
            when(mockCache.get("req-failed")).thenReturn(session);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            String body = responseOutput.getContent();
            Assert.assertTrue(body.contains("FAILED"),
                    "Response body should contain FAILED status");
            Assert.assertTrue(body.contains("Credential signature invalid"),
                    "Response body should contain the failure reason");
        }
    }

    @Test(priority = 7, description = "Test doGet returns 200 with requestId in the response body")
    public void testDoGetResponseContainsRequestId() throws Exception {

        when(request.getParameter("requestId")).thenReturn("req-id-check");

        try (MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            VPFlowSession session = new VPFlowSession.Builder()
                    .requestId("req-id-check")
                    .status(VPFlowStatus.ACTIVE)
                    .build();
            when(mockCache.get("req-id-check")).thenReturn(session);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            Assert.assertTrue(responseOutput.getContent().contains("req-id-check"),
                    "Response body should contain the requestId");
        }
    }

}
