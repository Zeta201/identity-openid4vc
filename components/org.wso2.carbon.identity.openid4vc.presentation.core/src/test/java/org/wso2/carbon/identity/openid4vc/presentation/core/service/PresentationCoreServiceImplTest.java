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

package org.wso2.carbon.identity.openid4vc.presentation.core.service;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionRespDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSessionStatus;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.impl.PresentationCoreServiceImpl;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PresentationCoreServiceImpl}.
 */
public class PresentationCoreServiceImplTest {

    private static final String REQUEST_ID = "req-test-001";
    private static final int SUPER_TENANT_ID = MultitenantConstants.SUPER_TENANT_ID;

    private PresentationCoreServiceImpl service;
    private VPSessionCache mockCache;
    private MockedStatic<VPSessionCache> vpSessionCacheMockedStatic;

    @BeforeMethod
    public void setUp() {

        service = new PresentationCoreServiceImpl();
        mockCache = mock(VPSessionCache.class);
        vpSessionCacheMockedStatic = mockStatic(VPSessionCache.class);
        vpSessionCacheMockedStatic.when(VPSessionCache::getInstance).thenReturn(mockCache);
    }

    @AfterMethod
    public void tearDown() {

        if (vpSessionCacheMockedStatic != null) {
            vpSessionCacheMockedStatic.close();
        }
    }

    // -------------------------------------------------------------------------
    // getPresentationSession
    // -------------------------------------------------------------------------

    @Test(priority = 1, description = "Test getPresentationSession throws VP_REQUEST_NOT_FOUND when session absent")
    public void testGetPresentationSessionNotFound() {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(null);

        try {
            service.getPresentationSession(REQUEST_ID);
            Assert.fail("Expected PresentationCoreClientException");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    "Error code should be VP_REQUEST_NOT_FOUND");
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 2, description = "Test getPresentationSession throws VP_REQUEST_EXPIRED when session is expired")
    public void testGetPresentationSessionExpired() {

        VPSession expiredSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() - 1000) // already expired
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(expiredSession));

        try {
            service.getPresentationSession(REQUEST_ID);
            Assert.fail("Expected PresentationCoreClientException");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_EXPIRED.getCode(),
                    "Error code should be VP_REQUEST_EXPIRED");
            verify(mockCache).clearCacheEntry(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID));
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 3, description = "Test getPresentationSession returns active session successfully")
    public void testGetPresentationSessionActiveSuccess() throws PresentationCoreException {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        VPSession result = service.getPresentationSession(REQUEST_ID);

        Assert.assertNotNull(result, "Session should be returned");
        Assert.assertEquals(result.getRequestId(), REQUEST_ID);
        Assert.assertEquals(result.getStatus(), VPSessionStatus.ACTIVE);
        verify(mockCache, never()).clearCacheEntry(any(), any(int.class));
    }

    // -------------------------------------------------------------------------
    // handleSessionFailed
    // -------------------------------------------------------------------------

    @Test(priority = 4, description = "Test handleSessionFailed sets FAILED status and persists to cache")
    public void testHandleSessionFailedSetsStatusAndPersists() {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .tenantDomain("carbon.super")
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        service.handleSessionFailed(REQUEST_ID, "invalid_request", "Something went wrong.");

        Assert.assertEquals(activeSession.getStatus(), VPSessionStatus.FAILED,
                "Session status should be FAILED");
        Assert.assertEquals(activeSession.getErrorType(), "invalid_request");
        Assert.assertEquals(activeSession.getErrorDescription(), "Something went wrong.");
        verify(mockCache).addToCache(any(VPSessionCacheKey.class), any(VPSessionCacheEntry.class),
                eq(SUPER_TENANT_ID));
    }

    @Test(priority = 5, description = "Test handleSessionFailed is a no-op when session is not found")
    public void testHandleSessionFailedSessionNotFound() {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(null);

        service.handleSessionFailed(REQUEST_ID, "server_error", "Internal error.");

        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    @Test(priority = 6, description = "Test handleSessionFailed is a no-op when session already VERIFIED")
    public void testHandleSessionFailedNoOpWhenAlreadyVerified() {

        VPSession verifiedSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.VERIFIED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(verifiedSession));

        service.handleSessionFailed(REQUEST_ID, "server_error", "Late error.");

        Assert.assertEquals(verifiedSession.getStatus(), VPSessionStatus.VERIFIED,
                "Already-verified session should not be overwritten");
        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    @Test(priority = 7, description = "Test handleSessionFailed is a no-op for blank requestId")
    public void testHandleSessionFailedBlankRequestId() {

        service.handleSessionFailed("", "server_error", "Error.");

        verify(mockCache, never()).getValueFromCache(any(), any(int.class));
    }

    // -------------------------------------------------------------------------
    // handleSessionVerified
    // -------------------------------------------------------------------------

    @Test(priority = 8, description = "Test handleSessionVerified sets VERIFIED status and persists to cache")
    public void testHandleSessionVerifiedSetsStatusAndPersists() {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .tenantDomain("carbon.super")
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        VerificationResponseDTO verificationResponse = mock(VerificationResponseDTO.class);
        when(verificationResponse.getCredentialId()).thenReturn("cred-001");

        service.handleSessionVerified(REQUEST_ID, verificationResponse);

        Assert.assertEquals(activeSession.getStatus(), VPSessionStatus.VERIFIED,
                "Session status should be VERIFIED");
        Assert.assertEquals(activeSession.getVerificationResponse(), verificationResponse,
                "Verification response should be stored on session");
        verify(mockCache).addToCache(any(VPSessionCacheKey.class), any(VPSessionCacheEntry.class),
                eq(SUPER_TENANT_ID));
    }

    @Test(priority = 9, description = "Test handleSessionVerified is a no-op when session is not found")
    public void testHandleSessionVerifiedSessionNotFound() {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(null);

        service.handleSessionVerified(REQUEST_ID, mock(VerificationResponseDTO.class));

        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    // -------------------------------------------------------------------------
    // getPresentationSessionStatus
    // -------------------------------------------------------------------------

    @Test(priority = 10, description = "Test getPresentationSessionStatus returns null when session absent")
    public void testGetPresentationSessionResultNotFound() {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(null);

        VerificationSessionRespDTO result = service.getPresentationSessionStatus(REQUEST_ID);

        Assert.assertNull(result, "Should return null when no session exists");
    }

    @Test(priority = 11, description = "Test getPresentationSessionStatus returns ACTIVE status without removing session")
    public void testGetPresentationSessionResultActiveSession() {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        VerificationSessionRespDTO result = service.getPresentationSessionStatus(REQUEST_ID);

        Assert.assertNotNull(result, "Result should not be null");
        Assert.assertEquals(result.getStatus(), VPSessionStatus.ACTIVE);
        verify(mockCache, never()).clearCacheEntry(any(), any(int.class));
    }

    @Test(priority = 12, description = "Test getPresentationSessionStatus removes session when status is VERIFIED")
    public void testGetPresentationSessionResultVerifiedRemovesSession() {

        VerificationResponseDTO verificationResponse = mock(VerificationResponseDTO.class);
        VPSession verifiedSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.VERIFIED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        verifiedSession.setVerificationResponse(verificationResponse);
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(verifiedSession));

        VerificationSessionRespDTO result = service.getPresentationSessionStatus(REQUEST_ID);

        Assert.assertEquals(result.getStatus(), VPSessionStatus.VERIFIED);
        Assert.assertEquals(result.getVerificationResponse(), verificationResponse);
        verify(mockCache).clearCacheEntry(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID));
    }

    @Test(priority = 13, description = "Test getPresentationSessionStatus removes session when status is FAILED")
    public void testGetPresentationSessionResultFailedRemovesSession() {

        VPSession failedSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .status(VPSessionStatus.FAILED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        failedSession.setErrorType("server_error");
        failedSession.setErrorDescription("Something failed.");
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(failedSession));

        VerificationSessionRespDTO result = service.getPresentationSessionStatus(REQUEST_ID);

        Assert.assertEquals(result.getStatus(), VPSessionStatus.FAILED);
        Assert.assertEquals(result.getErrorType(), "server_error");
        verify(mockCache).clearCacheEntry(any(VPSessionCacheKey.class), eq(SUPER_TENANT_ID));
    }
}
