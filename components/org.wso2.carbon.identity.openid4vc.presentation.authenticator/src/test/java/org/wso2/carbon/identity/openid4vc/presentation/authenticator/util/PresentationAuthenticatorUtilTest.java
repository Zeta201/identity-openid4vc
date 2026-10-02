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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PresentationAuthenticatorUtil}.
 * Tests subject identifier resolution and subject claim name resolution.
 */
public class PresentationAuthenticatorUtilTest {

    // -------------------------------------------------------------------------
    // resolveSubjectIdentifier
    // -------------------------------------------------------------------------

    @Test(priority = 1, description = "Test resolveSubjectIdentifier returns namespaced ID when issuer is present")
    public void testResolveSubjectIdentifierWithIssuerAndMatchingClaim() {

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "alice@example.com");
        VerificationResponseDTO metadata = new VerificationResponseDTO();
        metadata.setIssuer("https://issuer.example.com");

        String result = PresentationAuthenticatorUtil.resolveSubjectIdentifier(claims, "email", metadata);

        Assert.assertEquals(result, "https://issuer.example.com#alice@example.com",
                "Result should be namespaced with issuer when issuer is present");
    }

    @Test(priority = 2, description = "Test resolveSubjectIdentifier returns raw claim value when metadata is null")
    public void testResolveSubjectIdentifierWithNullMetadata() {

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user-42");

        Assert.assertEquals(PresentationAuthenticatorUtil.resolveSubjectIdentifier(claims, "sub", null), "user-42",
                "Result should be the raw claim value when metadata is null");
    }

    @Test(priority = 3, description = "Test resolveSubjectIdentifier returns raw claim value when issuer is blank")
    public void testResolveSubjectIdentifierWithBlankIssuer() {

        Map<String, Object> claims = Collections.singletonMap("sub", "user-42");
        VerificationResponseDTO metadata = new VerificationResponseDTO();
        metadata.setIssuer("");

        Assert.assertEquals(PresentationAuthenticatorUtil.resolveSubjectIdentifier(claims, "sub", metadata), "user-42",
                "Result should be the raw claim value when issuer is blank");
    }

    @Test(priority = 4,
            description = "Test resolveSubjectIdentifier returns null when the subject claim is not in the map")
    public void testResolveSubjectIdentifierWithAbsentClaim() {

        Map<String, Object> claims = Collections.singletonMap("email", "alice@example.com");

        Assert.assertNull(PresentationAuthenticatorUtil.resolveSubjectIdentifier(claims, "sub", null),
                "Result should be null when the subject claim is absent from the claims map");
    }

    @Test(priority = 5, description = "Test resolveSubjectIdentifier returns null when subject claim name is null")
    public void testResolveSubjectIdentifierWithNullClaimName() {

        Map<String, Object> claims = Collections.singletonMap("sub", "user-42");

        Assert.assertNull(PresentationAuthenticatorUtil.resolveSubjectIdentifier(claims, null, null),
                "Result should be null when subject claim name is null");
    }

    @Test(priority = 6, description = "Test resolveSubjectIdentifier returns null when subject claim name is blank")
    public void testResolveSubjectIdentifierWithBlankClaimName() {

        Map<String, Object> claims = Collections.singletonMap("sub", "user-42");

        Assert.assertNull(PresentationAuthenticatorUtil.resolveSubjectIdentifier(claims, "   ", null),
                "Result should be null when subject claim name is blank");
    }

    @Test(priority = 7, description = "Test resolveSubjectIdentifier returns null when the claims map is empty")
    public void testResolveSubjectIdentifierWithEmptyClaims() {

        Assert.assertNull(PresentationAuthenticatorUtil.resolveSubjectIdentifier(
                        Collections.emptyMap(), "email", null),
                "Result should be null when the claims map is empty");
    }

    // -------------------------------------------------------------------------
    // resolveSubjectClaimName
    // -------------------------------------------------------------------------

    @Test(priority = 8, description = "Test resolveSubjectClaimName returns null when IdP config is null")
    public void testResolveSubjectClaimNameWithNullConfig() {

        Assert.assertNull(PresentationAuthenticatorUtil.resolveSubjectClaimName(null),
                "Result should be null when the IdP config is null");
    }

    @Test(priority = 9, description = "Test resolveSubjectClaimName returns null when claim config is null")
    public void testResolveSubjectClaimNameWithNullClaimConfig() {

        ExternalIdPConfig mockConfig = mock(ExternalIdPConfig.class);
        IdentityProvider mockIdP = mock(IdentityProvider.class);
        when(mockConfig.getIdentityProvider()).thenReturn(mockIdP);
        when(mockIdP.getClaimConfig()).thenReturn(null);

        Assert.assertNull(PresentationAuthenticatorUtil.resolveSubjectClaimName(mockConfig),
                "Result should be null when the claim config is null");
    }

    @Test(priority = 10, description = "Test resolveSubjectClaimName returns the user claim URI from the claim config")
    public void testResolveSubjectClaimNameWithValidUri() {

        ExternalIdPConfig mockConfig = mock(ExternalIdPConfig.class);
        IdentityProvider mockIdP = mock(IdentityProvider.class);
        ClaimConfig mockClaimConfig = mock(ClaimConfig.class);
        when(mockConfig.getIdentityProvider()).thenReturn(mockIdP);
        when(mockIdP.getClaimConfig()).thenReturn(mockClaimConfig);
        when(mockClaimConfig.getUserClaimURI()).thenReturn("email");

        Assert.assertEquals(PresentationAuthenticatorUtil.resolveSubjectClaimName(mockConfig), "email",
                "Result should be the user claim URI from the claim config");
    }
}
