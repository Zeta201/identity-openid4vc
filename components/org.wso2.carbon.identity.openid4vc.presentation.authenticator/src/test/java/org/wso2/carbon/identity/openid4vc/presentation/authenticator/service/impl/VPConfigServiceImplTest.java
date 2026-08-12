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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.OpenID4VPTenantConfigCache;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link VPConfigServiceImpl}.
 */
public class VPConfigServiceImplTest {

    private MockedStatic<OpenID4VPTenantConfigCache> mockedConfigCache;
    private OpenID4VPTenantConfigCache mockConfigCacheInstance;

    @Mock
    private RegistryService registryService;
    @Mock
    private UserRegistry registry;
    @Mock
    private Resource resource;

    private VPConfigServiceImpl configService;

    @BeforeClass
    public void setUpClass() {

        mockConfigCacheInstance = Mockito.mock(OpenID4VPTenantConfigCache.class);
        mockedConfigCache = Mockito.mockStatic(OpenID4VPTenantConfigCache.class);
        mockedConfigCache.when(OpenID4VPTenantConfigCache::getInstance).thenReturn(mockConfigCacheInstance);
    }

    @AfterClass
    public void tearDownClass() {

        if (mockedConfigCache != null) {
            mockedConfigCache.close();
        }
    }

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        configService = new VPConfigServiceImpl();
    }

    @Test(priority = 1,
            description = "Test that TenantConfig getters return null by default and setters persist values")
    public void testTenantConfigGettersSetters() {

        // Verify defaults
        VPConfigService.TenantConfig config = new VPConfigService.TenantConfig();
        Assert.assertNull(config.getClientIdScheme(),
                "clientIdScheme should be null before being set");
        Assert.assertNull(config.getResponseMode(),
                "responseMode should be null before being set");

        // Set values and verify persistence
        config.setClientIdScheme(VPConstants.DEFAULT_CLIENT_ID_SCHEME);
        config.setResponseMode(VPConstants.DEFAULT_RESPONSE_MODE);

        Assert.assertEquals(config.getClientIdScheme(), VPConstants.DEFAULT_CLIENT_ID_SCHEME,
                "clientIdScheme should match the value that was set");
        Assert.assertEquals(config.getResponseMode(), VPConstants.DEFAULT_RESPONSE_MODE,
                "responseMode should match the value that was set");
    }

    @Test(priority = 2,
            description = "Test that getConfig returns an empty TenantConfig when registry path does not exist")
    public void testGetConfigReturnsEmptyWhenPathAbsent() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            // Set up tenant and registry stubs with no existing resource
            utilMock.when(() -> IdentityTenantUtil.getTenantId("example.com")).thenReturn(1);
            utilMock.when(IdentityTenantUtil::getRegistryService).thenReturn(registryService);
            when(registryService.getGovernanceSystemRegistry(1)).thenReturn(registry);
            when(registry.resourceExists(VPConfigServiceImpl.REGISTRY_PATH)).thenReturn(false);

            // Execute test
            VPConfigService.TenantConfig config = configService.getConfig("example.com");

            // Verify an empty config is returned
            Assert.assertNotNull(config,
                    "getConfig should return a non-null TenantConfig even when the registry path is absent");
            Assert.assertNull(config.getClientIdScheme(),
                    "clientIdScheme should be null when registry path is absent");
            Assert.assertNull(config.getResponseMode(),
                    "responseMode should be null when registry path is absent");
        }
    }

    @Test(priority = 3,
            description = "Test that getConfig reads clientIdScheme and responseMode from the registry resource")
    public void testGetConfigReadsPropertiesFromRegistry() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            // Set up registry with a stored resource
            utilMock.when(() -> IdentityTenantUtil.getTenantId("example.com")).thenReturn(1);
            utilMock.when(IdentityTenantUtil::getRegistryService).thenReturn(registryService);
            when(registryService.getGovernanceSystemRegistry(1)).thenReturn(registry);
            when(registry.resourceExists(VPConfigServiceImpl.REGISTRY_PATH)).thenReturn(true);
            when(registry.get(VPConfigServiceImpl.REGISTRY_PATH)).thenReturn(resource);
            when(resource.getProperty("clientIdScheme")).thenReturn(VPConstants.DEFAULT_CLIENT_ID_SCHEME);
            when(resource.getProperty("responseMode")).thenReturn("direct_post.jwt");

            // Execute test
            VPConfigService.TenantConfig config = configService.getConfig("example.com");

            // Verify properties are read correctly
            Assert.assertEquals(config.getClientIdScheme(), VPConstants.DEFAULT_CLIENT_ID_SCHEME,
                    "clientIdScheme should match the value stored in the registry resource");
            Assert.assertEquals(config.getResponseMode(), "direct_post.jwt",
                    "responseMode should match the value stored in the registry resource");
        }
    }

    @Test(priority = 4,
            description = "Test that getConfig wraps a RegistryException in a VPAuthenticatorServerException",
            expectedExceptions = VPAuthenticatorServerException.class)
    public void testGetConfigThrowsOnRegistryException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            // Set up registry to throw on access
            utilMock.when(() -> IdentityTenantUtil.getTenantId("example.com")).thenReturn(1);
            utilMock.when(IdentityTenantUtil::getRegistryService).thenReturn(registryService);
            when(registryService.getGovernanceSystemRegistry(1)).thenThrow(new RegistryException("DB error"));

            // Execute test — should throw VPAuthenticatorServerException
            configService.getConfig("example.com");
        }
    }

    @Test(priority = 5, description = "Test that setConfig persists both properties to the registry via Registry.put")
    public void testSetConfigPutsResourceInRegistry() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            // Set up registry to accept a new resource
            utilMock.when(() -> IdentityTenantUtil.getTenantId("example.com")).thenReturn(1);
            utilMock.when(IdentityTenantUtil::getRegistryService).thenReturn(registryService);
            when(registryService.getGovernanceSystemRegistry(1)).thenReturn(registry);
            when(registry.resourceExists(VPConfigServiceImpl.REGISTRY_PATH)).thenReturn(false);
            when(registry.newResource()).thenReturn(resource);

            // Build and save config
            VPConfigService.TenantConfig config = new VPConfigService.TenantConfig();
            config.setClientIdScheme(VPConstants.DEFAULT_CLIENT_ID_SCHEME);
            config.setResponseMode(VPConstants.DEFAULT_RESPONSE_MODE);

            // Execute test
            configService.setConfig(config, "example.com");

            // Verify the resource was persisted at the correct registry path
            verify(registry).put(eq(VPConfigServiceImpl.REGISTRY_PATH), eq(resource));
        }
    }

    @Test(priority = 6,
            description = "Test that setConfig wraps a RegistryException in a VPAuthenticatorServerException",
            expectedExceptions = VPAuthenticatorServerException.class)
    public void testSetConfigThrowsOnRegistryException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            // Set up registry to throw on access
            utilMock.when(() -> IdentityTenantUtil.getTenantId("example.com")).thenReturn(1);
            utilMock.when(IdentityTenantUtil::getRegistryService).thenReturn(registryService);
            when(registryService.getGovernanceSystemRegistry(1)).thenThrow(new RegistryException("DB error"));

            // Execute test — should throw VPAuthenticatorServerException
            configService.setConfig(new VPConfigService.TenantConfig(), "example.com");
        }
    }

    @Test(priority = 7,
            description = "Test that getConfigByTenantId resolves the tenant domain and delegates to getConfig")
    public void testGetConfigByTenantIdDelegatesToGetConfig() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            // Set up tenant ID to domain resolution
            utilMock.when(() -> IdentityTenantUtil.getTenantDomain(5)).thenReturn("tenant5.com");
            utilMock.when(() -> IdentityTenantUtil.getTenantId("tenant5.com")).thenReturn(5);
            utilMock.when(IdentityTenantUtil::getRegistryService).thenReturn(registryService);
            when(registryService.getGovernanceSystemRegistry(5)).thenReturn(registry);
            when(registry.resourceExists(VPConfigServiceImpl.REGISTRY_PATH)).thenReturn(false);

            // Execute test
            VPConfigService.TenantConfig config = configService.getConfigByTenantId(5);

            // Verify a non-null config is returned
            Assert.assertNotNull(config,
                    "getConfigByTenantId should return a non-null TenantConfig");
        }
    }
}
