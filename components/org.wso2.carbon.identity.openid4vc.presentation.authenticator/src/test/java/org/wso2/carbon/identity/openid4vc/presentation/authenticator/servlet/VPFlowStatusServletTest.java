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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.store.VPSessionStore;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link VPFlowStatusServlet}.
 * Verifies pollToken-based session status polling.
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

    @Test(priority = 1, description = "Test doGet returns 400 when pollToken parameter is absent")
    public void testDoGetMissingPollToken() throws Exception {

        when(request.getParameter("pollToken")).thenReturn(null);

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("pollToken"),
                "Response body should reference the missing pollToken parameter");
    }

    @Test(priority = 2, description = "Test doGet returns 400 when pollToken parameter is blank")
    public void testDoGetBlankPollToken() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("   ");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("invalid_request"),
                "Response body should contain error code invalid_request");
    }

    @Test(priority = 3, description = "Test doGet returns 200 NOT_FOUND when pollToken is not in the store")
    public void testDoGetPollTokenNotInStore() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("unknown-poll-token");

        try (MockedStatic<VPSessionStore> mockedStore = Mockito.mockStatic(VPSessionStore.class)) {
            VPSessionStore mockStore = mock(VPSessionStore.class);
            mockedStore.when(VPSessionStore::getInstance).thenReturn(mockStore);
            when(mockStore.getRequestIdByPollToken("unknown-poll-token")).thenReturn(null);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertTrue(responseOutput.getContent().contains("NOT_FOUND"),
                    "Response body should contain NOT_FOUND status when pollToken resolves to no session");
        }
    }

    @Test(priority = 4, description = "Test doGet returns 200 NOT_FOUND when session is absent from cache")
    public void testDoGetSessionNotInCache() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("valid-poll-token");

        try (MockedStatic<VPSessionStore> mockedStore = Mockito.mockStatic(VPSessionStore.class);
             MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {

            VPSessionStore mockStore = mock(VPSessionStore.class);
            mockedStore.when(VPSessionStore::getInstance).thenReturn(mockStore);
            when(mockStore.getRequestIdByPollToken("valid-poll-token")).thenReturn("req-cache-miss");

            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("req-cache-miss")).thenReturn(null);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            verify(response).setStatus(HttpServletResponse.SC_OK);
            Assert.assertTrue(responseOutput.getContent().contains("NOT_FOUND"),
                    "Response body should contain NOT_FOUND status when session is not in the cache");
        }
    }

    @Test(priority = 5, description = "Test doGet returns 200 ACTIVE for an active session")
    public void testDoGetActiveSession() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("active-poll-token");

        try (MockedStatic<VPSessionStore> mockedStore = Mockito.mockStatic(VPSessionStore.class);
             MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {

            VPSessionStore mockStore = mock(VPSessionStore.class);
            mockedStore.when(VPSessionStore::getInstance).thenReturn(mockStore);
            when(mockStore.getRequestIdByPollToken("active-poll-token")).thenReturn("req-active");

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

    @Test(priority = 6, description = "Test doGet returns 200 VERIFIED for a verified session")
    public void testDoGetVerifiedSession() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("verified-poll-token");

        try (MockedStatic<VPSessionStore> mockedStore = Mockito.mockStatic(VPSessionStore.class);
             MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {

            VPSessionStore mockStore = mock(VPSessionStore.class);
            mockedStore.when(VPSessionStore::getInstance).thenReturn(mockStore);
            when(mockStore.getRequestIdByPollToken("verified-poll-token")).thenReturn("req-verified");

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

    @Test(priority = 7, description = "Test doGet returns 200 FAILED with failure reason for a failed session")
    public void testDoGetFailedSession() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("failed-poll-token");

        try (MockedStatic<VPSessionStore> mockedStore = Mockito.mockStatic(VPSessionStore.class);
             MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {

            VPSessionStore mockStore = mock(VPSessionStore.class);
            mockedStore.when(VPSessionStore::getInstance).thenReturn(mockStore);
            when(mockStore.getRequestIdByPollToken("failed-poll-token")).thenReturn("req-failed");

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

    @Test(priority = 8, description = "Test doGet returns 200 with requestId in the response body")
    public void testDoGetResponseContainsRequestId() throws Exception {

        when(request.getParameter("pollToken")).thenReturn("id-check-token");

        try (MockedStatic<VPSessionStore> mockedStore = Mockito.mockStatic(VPSessionStore.class);
             MockedStatic<VPSessionCache> mockedCache = Mockito.mockStatic(VPSessionCache.class)) {

            VPSessionStore mockStore = mock(VPSessionStore.class);
            mockedStore.when(VPSessionStore::getInstance).thenReturn(mockStore);
            when(mockStore.getRequestIdByPollToken("id-check-token")).thenReturn("req-id-check");

            VPSessionCache mockCache = mock(VPSessionCache.class);
            mockedCache.when(VPSessionCache::getInstance).thenReturn(mockCache);
            VPFlowSession session = new VPFlowSession.Builder()
                    .requestId("req-id-check")
                    .status(VPFlowStatus.ACTIVE)
                    .build();
            when(mockCache.get("req-id-check")).thenReturn(session);

            servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

            Assert.assertTrue(responseOutput.getContent().contains("req-id-check"),
                    "Response body should contain the resolved requestId");
        }
    }

}
