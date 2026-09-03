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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link VPFlowServiceImpl}.
 */
public class VPFlowServiceImplTest {

    private VPFlowServiceImpl service;

    @BeforeClass
    public void setUpCarbonHome() {

        System.setProperty("carbon.home", System.getProperty("java.io.tmpdir"));
    }

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        service = new VPFlowServiceImpl();
    }

    @Test(priority = 1,
            description = "Test that initiate throws VPAuthenticatorClientException when definitionId is blank")
    public void testInitiateBlankDefinitionIdThrows() {

        // Execute test — blank definitionId should fail validation
        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate("", "example.com", 30_000L));
    }

    @Test(priority = 2,
            description = "Test that initiate throws VPAuthenticatorClientException when definitionId is null")
    public void testInitiateNullDefinitionIdThrows() {

        // Execute test — null definitionId should fail validation
        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate(null, "example.com", 30_000L));
    }

    @Test(priority = 3,
            description = "Test that initiate throws VPAuthenticatorClientException when tenantDomain is blank")
    public void testInitiateBlankTenantDomainThrows() {

        // Execute test — blank tenantDomain should fail validation
        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate("def-id", "", 30_000L));
    }

    @Test(priority = 4,
            description = "Test that initiate throws VPAuthenticatorClientException when tenantDomain is null")
    public void testInitiateNullTenantDomainThrows() {

        // Execute test — null tenantDomain should fail validation
        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate("def-id", null, 30_000L));
    }

    @Test(priority = 5, description = "Test that initiate validation failure carries the INVALID_REQUEST error code")
    public void testInitiateValidationErrorCodeIsInvalidRequest() {

        try {
            // Execute test
            service.initiate("", "example.com", 30_000L);
        } catch (VPAuthenticatorClientException e) {
            // Verify the error code is INVALID_REQUEST
            Assert.assertEquals(e.getCode(), VPAuthenticatorErrorCode.INVALID_REQUEST.getCode(),
                    "Validation error code should be INVALID_REQUEST");
        } catch (VPAuthenticatorException e) {
            throw new RuntimeException("Unexpected exception type", e);
        }
    }

    @Test(priority = 6,
            description = "Test that createAuthorizationRequestJwt throws VP_REQUEST_NOT_FOUND when session is missing")
    public void testGenerateRequestJwtSessionNotFound() throws VPAuthenticatorServerException {

        try (MockedStatic<VPSessionCache> mocked = Mockito.mockStatic(VPSessionCache.class)) {
            // Set up cache to return null for the given transaction ID
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mocked.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("unknown-txn")).thenReturn(null);

            try {
                // Execute test
                service.createAuthorizationRequestJwt("unknown-txn");
                throw new AssertionError("Expected VPAuthenticatorClientException");
            } catch (VPAuthenticatorClientException e) {
                // Verify the error code indicates the session was not found
                Assert.assertEquals(e.getCode(), VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                        "Error code should be VP_REQUEST_NOT_FOUND when the session is missing");
            } catch (VPAuthenticatorException e) {
                throw new RuntimeException("Unexpected exception type", e);
            }
        }
    }

    @Test(priority = 7, description = "Test that getSession returns null when no session exists for the given ID")
    public void testGetSessionReturnsNullForUnknownId() throws VPAuthenticatorServerException {

        try (MockedStatic<VPSessionCache> mocked = Mockito.mockStatic(VPSessionCache.class)) {
            // Set up cache to return null
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mocked.when(VPSessionCache::getInstance).thenReturn(mockCache);
            when(mockCache.get("unknown-txn")).thenReturn(null);

            // Execute test
            VPFlowSession result = service.getSession("unknown-txn");

            // Verify
            Assert.assertNull(result,
                    "getSession should return null when the cache has no entry for the given ID");
        }
    }

    @Test(priority = 8, description = "Test that getSession returns the stored session when the ID exists in the cache")
    public void testGetSessionReturnsSessionWhenFound() throws VPAuthenticatorServerException {

        try (MockedStatic<VPSessionCache> mocked = Mockito.mockStatic(VPSessionCache.class)) {
            // Set up cache with a stored session
            VPSessionCache mockCache = mock(VPSessionCache.class);
            mocked.when(VPSessionCache::getInstance).thenReturn(mockCache);
            VPFlowSession session = new VPFlowSession();
            session.setRequestId("txn-123");
            when(mockCache.get("txn-123")).thenReturn(session);

            // Execute test
            VPFlowSession result = service.getSession("txn-123");

            // Verify the correct session is returned
            Assert.assertEquals(result.getRequestId(), "txn-123",
                    "getSession should return the session stored in the cache for the given ID");
        }
    }
}
