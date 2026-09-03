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

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link WalletSubmissionServlet}.
 * Covers only HTTP-layer concerns: feature guard, body size guard, and exception → status mapping.
 * Business-logic assertions (session state transitions, cache mutations, verification results)
 * belong in VPFlowServiceImplTest.
 */
public class WalletSubmissionServletTest {

    private WalletSubmissionServlet servlet;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private InMemoryServletOutputStream responseOutput;
    private VPFlowService mockService;

    @BeforeMethod
    public void setUp() throws Exception {

        servlet = new WalletSubmissionServlet();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        responseOutput = new InMemoryServletOutputStream();
        mockService = mock(VPFlowService.class);
        when(request.getMethod()).thenReturn("POST");
        when(response.getOutputStream()).thenReturn(responseOutput);
    }

    @AfterMethod
    public void tearDown() {

        VPDataHolder.setVPFlowService(null);
    }

    @Test(priority = 1, description = "Returns 501 when the OpenID4VP feature is not enabled")
    public void testDoPostWhenFeatureNotEnabled() throws Exception {

        VPDataHolder.setVPFlowService(null);

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                "OpenID4VP feature is not enabled.");
    }

    @Test(priority = 2, description = "Returns 413 when the request body exceeds the maximum allowed size")
    public void testDoPostWhenBodyTooLarge() throws Exception {

        VPDataHolder.setVPFlowService(mockService);
        when(request.getContentLength()).thenReturn(1024 * 1024 + 1);

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                "Request body exceeds maximum allowed size.");
    }

    @Test(priority = 3, description = "Returns 200 when processWalletResponse completes normally")
    public void testDoPostSuccess() throws Exception {

        VPDataHolder.setVPFlowService(mockService);
        doNothing().when(mockService).processWalletResponse(any());
        setupFormEncodedRequest("state=req-1&vp_token=%7B%22cred-1%22%3A%5B%22token1%22%5D%7D");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_OK);
        Assert.assertEquals(responseOutput.getContent(), "{}");
    }

    @Test(priority = 4, description = "Returns 400 when processWalletResponse throws a client exception")
    public void testDoPostClientError() throws Exception {

        VPDataHolder.setVPFlowService(mockService);
        doThrow(new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                "Missing state parameter."))
                .when(mockService).processWalletResponse(any());
        setupFormEncodedRequest("vp_token=%7B%22cred-1%22%3A%5B%22token1%22%5D%7D");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Assert.assertTrue(responseOutput.getContent().contains("Missing state parameter"),
                "Response body should contain the client error message");
    }

    @Test(priority = 5, description = "Returns 500 when processWalletResponse throws a server exception")
    public void testDoPostServerError() throws Exception {

        VPDataHolder.setVPFlowService(mockService);
        doThrow(new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                "Signing failed."))
                .when(mockService).processWalletResponse(any());
        setupFormEncodedRequest("state=req-1&vp_token=%7B%22cred-1%22%3A%5B%22token1%22%5D%7D");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    @Test(priority = 6, description = "Returns 500 when processWalletResponse throws an unexpected RuntimeException")
    public void testDoPostUnexpectedError() throws Exception {

        VPDataHolder.setVPFlowService(mockService);
        doThrow(new RuntimeException("unexpected"))
                .when(mockService).processWalletResponse(any());
        setupFormEncodedRequest("state=req-1&vp_token=%7B%22cred-1%22%3A%5B%22token1%22%5D%7D");

        servlet.service((javax.servlet.ServletRequest) request, (javax.servlet.ServletResponse) response);

        verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    /**
     * Configures the mock request as a form-urlencoded POST whose body is {@code formBody}.
     */
    private void setupFormEncodedRequest(String formBody) throws Exception {

        byte[] bodyBytes = formBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        when(request.getContentLength()).thenReturn(bodyBytes.length);
        when(request.getContentType()).thenReturn("application/x-www-form-urlencoded");
        when(request.getInputStream()).thenReturn(new InMemoryServletInputStream(bodyBytes));
    }
}
