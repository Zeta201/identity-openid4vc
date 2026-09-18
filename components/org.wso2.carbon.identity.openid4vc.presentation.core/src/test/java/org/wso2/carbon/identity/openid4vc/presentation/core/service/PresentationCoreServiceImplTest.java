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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VPVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
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
    private static final String TENANT_DOMAIN = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    private static final int TENANT_ID = MultitenantConstants.SUPER_TENANT_ID;

    // Attacker operates in a different tenant from the one that created the session.
    private static final String ATTACKER_TENANT_DOMAIN = "attacker.example.com";
    private static final int ATTACKER_TENANT_ID = 9999;

    private PresentationCoreServiceImpl service;
    private VPSessionCache mockCache;
    private MockedStatic<VPSessionCache> vpSessionCacheMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;

    @BeforeMethod
    public void setUp() {

        service = new PresentationCoreServiceImpl();
        mockCache = mock(VPSessionCache.class);
        vpSessionCacheMockedStatic = mockStatic(VPSessionCache.class);
        vpSessionCacheMockedStatic.when(VPSessionCache::getInstance).thenReturn(mockCache);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
    }

    @AfterMethod
    public void tearDown() {

        if (vpSessionCacheMockedStatic != null) {
            vpSessionCacheMockedStatic.close();
        }
        if (identityTenantUtilMockedStatic != null) {
            identityTenantUtilMockedStatic.close();
        }
    }

    // -------------------------------------------------------------------------
    // getPresentationSession
    // -------------------------------------------------------------------------

    @Test(priority = 1, description = "Test getPresentationSession throws VP_REQUEST_NOT_FOUND when session absent")
    public void testGetPresentationSessionNotFound() {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(null);

        try {
            service.getPresentationSession(REQUEST_ID, TENANT_DOMAIN);
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
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() - 1000) // already expired
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(expiredSession));

        try {
            service.getPresentationSession(REQUEST_ID, TENANT_DOMAIN);
            Assert.fail("Expected PresentationCoreClientException");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_EXPIRED.getCode(),
                    "Error code should be VP_REQUEST_EXPIRED");
            verify(mockCache).clearCacheEntry(any(VPSessionCacheKey.class), eq(TENANT_ID));
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 3, description = "Test getPresentationSession returns active session successfully")
    public void testGetPresentationSessionActiveSuccess() throws PresentationCoreException {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        VPSession result = service.getPresentationSession(REQUEST_ID, TENANT_DOMAIN);

        Assert.assertNotNull(result, "Session should be returned");
        Assert.assertEquals(result.getRequestId(), REQUEST_ID);
        Assert.assertEquals(result.getStatus(), VPSessionStatus.ACTIVE);
        verify(mockCache, never()).clearCacheEntry(any(), any(int.class));
    }

    // -------------------------------------------------------------------------
    // handleSessionFailed
    // -------------------------------------------------------------------------

    @Test(priority = 4, description = "Test handleSessionFailed sets FAILED status and persists to cache")
    public void testHandleSessionFailedSetsStatusAndPersists() throws PresentationCoreException {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        service.handleSessionFailed(REQUEST_ID, TENANT_DOMAIN, "invalid_request", "Something went wrong.");

        Assert.assertEquals(activeSession.getStatus(), VPSessionStatus.FAILED,
                "Session status should be FAILED");
        Assert.assertEquals(activeSession.getErrorType(), "invalid_request");
        Assert.assertEquals(activeSession.getErrorDescription(), "Something went wrong.");
        verify(mockCache).addToCache(any(VPSessionCacheKey.class), any(VPSessionCacheEntry.class),
                eq(TENANT_ID));
    }

    @Test(priority = 5, description = "Test handleSessionFailed is a no-op when session is not found")
    public void testHandleSessionFailedSessionNotFound() throws PresentationCoreException {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(null);

        service.handleSessionFailed(REQUEST_ID, TENANT_DOMAIN, "server_error", "Internal error.");

        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    @Test(priority = 6, description = "Test handleSessionFailed is a no-op when session already VERIFIED")
    public void testHandleSessionFailedNoOpWhenAlreadyVerified() throws PresentationCoreException {

        VPSession verifiedSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.VERIFIED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(verifiedSession));

        service.handleSessionFailed(REQUEST_ID, TENANT_DOMAIN, "server_error", "Late error.");

        Assert.assertEquals(verifiedSession.getStatus(), VPSessionStatus.VERIFIED,
                "Already-verified session should not be overwritten");
        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    @Test(priority = 7, description = "Test handleSessionFailed is a no-op for blank requestId")
    public void testHandleSessionFailedBlankRequestId() throws PresentationCoreException {

        service.handleSessionFailed("", TENANT_DOMAIN, "server_error", "Error.");

        verify(mockCache, never()).getValueFromCache(any(), any(int.class));
    }

    // -------------------------------------------------------------------------
    // handleSessionVerified
    // -------------------------------------------------------------------------

    @Test(priority = 8, description = "Test handleSessionVerified sets VERIFIED status and persists to cache")
    public void testHandleSessionVerifiedSetsStatusAndPersists() throws PresentationCoreException {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        VerificationResponseDTO verificationResponse = mock(VerificationResponseDTO.class);
        when(verificationResponse.getCredentialId()).thenReturn("cred-001");

        service.handleSessionVerified(REQUEST_ID, TENANT_DOMAIN, verificationResponse);

        Assert.assertEquals(activeSession.getStatus(), VPSessionStatus.VERIFIED,
                "Session status should be VERIFIED");
        Assert.assertEquals(activeSession.getVerificationResponse(), verificationResponse,
                "Verification response should be stored on session");
        verify(mockCache).addToCache(any(VPSessionCacheKey.class), any(VPSessionCacheEntry.class),
                eq(TENANT_ID));
    }

    @Test(priority = 9, description = "Test handleSessionVerified is a no-op when session is not found")
    public void testHandleSessionVerifiedSessionNotFound() throws PresentationCoreException {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(null);

        service.handleSessionVerified(REQUEST_ID, TENANT_DOMAIN, mock(VerificationResponseDTO.class));

        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    // -------------------------------------------------------------------------
    // getPresentationSessionResult
    // -------------------------------------------------------------------------

    @Test(priority = 10, description = "Test getPresentationSessionResult returns null when session absent")
    public void testGetPresentationSessionResultNotFound() throws PresentationCoreException {

        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(null);

        VPVerificationResultDTO result = service.getPresentationSessionResult(REQUEST_ID, TENANT_DOMAIN);

        Assert.assertNull(result, "Should return null when no session exists");
    }

    @Test(priority = 11, description = "getPresentationSessionResult throws when session is ACTIVE")
    public void testGetPresentationSessionResultActiveSession() {

        VPSession activeSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(activeSession));

        try {
            service.getPresentationSessionResult(REQUEST_ID, TENANT_DOMAIN);
            Assert.fail("Expected PresentationCoreClientException");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_SESSION_PENDING.getCode(),
                    "Error code should be VP_SESSION_PENDING");
            verify(mockCache, never()).clearCacheEntry(any(), any(int.class));
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 12, description = "Test getPresentationSessionResult keeps session in cache when VERIFIED")
    public void testGetPresentationSessionResultVerifiedKeepsSession() throws PresentationCoreException {

        VerificationResponseDTO verificationResponse = mock(VerificationResponseDTO.class);
        VPSession verifiedSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.VERIFIED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        verifiedSession.setVerificationResponse(verificationResponse);
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(verifiedSession));

        VPVerificationResultDTO result = service.getPresentationSessionResult(REQUEST_ID, TENANT_DOMAIN);

        Assert.assertEquals(result.getStatus(), VPSessionStatus.VERIFIED);
        Assert.assertEquals(result.getVerificationResponse(), verificationResponse);
        verify(mockCache, never()).clearCacheEntry(any(VPSessionCacheKey.class), eq(TENANT_ID));
    }

    @Test(priority = 13, description = "Test getPresentationSessionResult keeps session in cache when FAILED")
    public void testGetPresentationSessionResultFailedKeepsSession() throws PresentationCoreException {

        VPSession failedSession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .status(VPSessionStatus.FAILED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        failedSession.setErrorType("server_error");
        failedSession.setErrorDescription("Something failed.");
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(failedSession));

        VPVerificationResultDTO result = service.getPresentationSessionResult(REQUEST_ID, TENANT_DOMAIN);

        Assert.assertEquals(result.getStatus(), VPSessionStatus.FAILED);
        Assert.assertEquals(result.getErrorType(), "server_error");
        verify(mockCache, never()).clearCacheEntry(any(VPSessionCacheKey.class), eq(TENANT_ID));
    }

    // -------------------------------------------------------------------------
    // Cross-tenant attack scenarios
    //
    // Tenant A generates a VP session (QR code).  An attacker operating in
    // Tenant B obtains the requestId (e.g. from a leaked QR scan) and tries
    // every public API surface using their own tenant context.  The cache is
    // mocked to simulate a cache-key collision so the attacker's lookup
    // actually returns Tenant A's session — the tenantId guard on the session
    // object itself is the last line of defence.
    // -------------------------------------------------------------------------

    /**
     * Builds a session that belongs to Tenant A and mocks the cache so that
     * a lookup keyed by ATTACKER_TENANT_ID still finds it (collision scenario).
     */
    private VPSession buildTenantASession() {

        return new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)           // owned by Tenant A
                .tenantDomain(TENANT_DOMAIN)
                .status(VPSessionStatus.ACTIVE)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
    }

    private void mockAttackerTenantId() {

        identityTenantUtilMockedStatic.when(
                () -> IdentityTenantUtil.getTenantId(ATTACKER_TENANT_DOMAIN))
                .thenReturn(ATTACKER_TENANT_ID);
    }

    @Test(priority = 14,
            description = "Cross-tenant: attacker from Tenant B cannot scan Tenant A's QR (getPresentationSession)")
    public void testGetPresentationSessionCrossTenantAttackBlocked() {

        mockAttackerTenantId();
        VPSession tenantASession = buildTenantASession();
        // Simulate a cache collision: attacker's lookup returns Tenant A's session object.
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(ATTACKER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(tenantASession));

        try {
            service.getPresentationSession(REQUEST_ID, ATTACKER_TENANT_DOMAIN);
            Assert.fail("Expected VP_REQUEST_NOT_FOUND for cross-tenant access");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    "Cross-tenant access must surface as NOT_FOUND to avoid leaking session existence");
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
        // Session must not be evicted — Tenant A's session must remain intact.
        verify(mockCache, never()).clearCacheEntry(any(), any(int.class));
    }

    @Test(priority = 15,
            description = "Cross-tenant: attacker from Tenant B cannot poll Tenant A's session status")
    public void testGetVerificationSessionStatusCrossTenantAttackBlocked() {

        mockAttackerTenantId();
        VPSession tenantASession = buildTenantASession();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(ATTACKER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(tenantASession));

        try {
            service.getVerificationSessionStatus(REQUEST_ID, ATTACKER_TENANT_DOMAIN);
            Assert.fail("Expected VP_REQUEST_NOT_FOUND for cross-tenant access");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode());
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 16,
            description = "Cross-tenant: attacker from Tenant B cannot read Tenant A's verification result")
    public void testGetPresentationSessionResultCrossTenantAttackBlocked() {

        mockAttackerTenantId();
        VPSession tenantASession = new VPSession.Builder()
                .requestId(REQUEST_ID)
                .tenantId(TENANT_ID)
                .tenantDomain(TENANT_DOMAIN)
                .status(VPSessionStatus.VERIFIED)
                .expiresAt(System.currentTimeMillis() + 120_000)
                .build();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(ATTACKER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(tenantASession));

        try {
            service.getPresentationSessionResult(REQUEST_ID, ATTACKER_TENANT_DOMAIN);
            Assert.fail("Expected VP_REQUEST_NOT_FOUND for cross-tenant access");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode(),
                    "Attacker must not be able to read Tenant A's verified credential data");
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
        // Session must not be evicted by the attacker's request.
        verify(mockCache, never()).clearCacheEntry(any(), any(int.class));
    }

    @Test(priority = 17,
            description = "Cross-tenant: attacker from Tenant B cannot poison Tenant A's session as failed")
    public void testHandleSessionFailedCrossTenantAttackBlocked() {

        mockAttackerTenantId();
        VPSession tenantASession = buildTenantASession();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(ATTACKER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(tenantASession));

        try {
            service.handleSessionFailed(REQUEST_ID, ATTACKER_TENANT_DOMAIN, "poisoned", "Injected failure.");
            Assert.fail("Expected VP_REQUEST_NOT_FOUND for cross-tenant access");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode());
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
        // Tenant A's session status must be unchanged and must not be written back.
        Assert.assertEquals(tenantASession.getStatus(), VPSessionStatus.ACTIVE,
                "Attacker must not be able to transition Tenant A's session to FAILED");
        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }

    @Test(priority = 18,
            description = "Cross-tenant: attacker from Tenant B cannot forge a verified result on Tenant A's session")
    public void testHandleSessionVerifiedCrossTenantAttackBlocked() {

        mockAttackerTenantId();
        VPSession tenantASession = buildTenantASession();
        when(mockCache.getValueFromCache(any(VPSessionCacheKey.class), eq(ATTACKER_TENANT_ID)))
                .thenReturn(new VPSessionCacheEntry(tenantASession));

        try {
            service.handleSessionVerified(REQUEST_ID, ATTACKER_TENANT_DOMAIN,
                    mock(VerificationResponseDTO.class));
            Assert.fail("Expected VP_REQUEST_NOT_FOUND for cross-tenant access");
        } catch (PresentationCoreClientException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode());
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreClientException, got: " + e.getClass().getSimpleName());
        }
        // Tenant A's session must remain ACTIVE — attacker cannot forge a successful verification.
        Assert.assertEquals(tenantASession.getStatus(), VPSessionStatus.ACTIVE,
                "Attacker must not be able to forge VERIFIED status on Tenant A's session");
        verify(mockCache, never()).addToCache(any(), any(), any(int.class));
    }
}
