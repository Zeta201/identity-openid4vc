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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;

import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RETRIEVE_RESOURCE_TYPE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPConfigServiceImpl.VP_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPConfigServiceImpl.VP_CONFIG_RESOURCE_TYPE_NAME;

/**
 * Unit tests for {@link VPConfigServiceImpl}.
 */
public class VPConfigServiceImplTest {

    @Mock
    private ConfigurationManager configurationManager;

    private VPConfigServiceImpl configService;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        VPDataHolder.setConfigurationManager(configurationManager);
        configService = new VPConfigServiceImpl();
    }

    @AfterMethod
    public void tearDown() {

        VPDataHolder.setConfigurationManager(null);
    }

    @Test(priority = 1,
            description = "Test that TenantConfig getters return null by default and setters persist values")
    public void testTenantConfigGettersSetters() {

        VPConfigService.TenantConfig config = new VPConfigService.TenantConfig();
        Assert.assertNull(config.getClientIdScheme(),
                "clientIdScheme should be null before being set");
        Assert.assertNull(config.getResponseMode(),
                "responseMode should be null before being set");

        config.setClientIdScheme(VPConstants.DEFAULT_CLIENT_ID_SCHEME);
        config.setResponseMode(VPConstants.DEFAULT_RESPONSE_MODE);

        Assert.assertEquals(config.getClientIdScheme(), VPConstants.DEFAULT_CLIENT_ID_SCHEME,
                "clientIdScheme should match the value that was set");
        Assert.assertEquals(config.getResponseMode(), VPConstants.DEFAULT_RESPONSE_MODE,
                "responseMode should match the value that was set");
    }

    @Test(priority = 2,
            description = "Test that getConfig returns an empty TenantConfig when the resource does not exist")
    public void testGetConfigReturnsEmptyWhenResourceAbsent() throws Exception {

        ConfigurationManagementException notFound = new ConfigurationManagementException(
                ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
        when(configurationManager.getResource(VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true))
                .thenThrow(notFound);

        VPConfigService.TenantConfig config = configService.getConfig("example.com");

        Assert.assertNotNull(config,
                "getConfig should return a non-null TenantConfig even when the resource is absent");
        Assert.assertNull(config.getClientIdScheme(),
                "clientIdScheme should be null when resource is absent");
        Assert.assertNull(config.getResponseMode(),
                "responseMode should be null when resource is absent");
    }

    @Test(priority = 3,
            description = "Test that getConfig reads clientIdScheme and responseMode from resource attributes")
    public void testGetConfigReadsAttributes() throws Exception {

        Attribute clientIdSchemeAttr = new Attribute("clientIdScheme", VPConstants.DEFAULT_CLIENT_ID_SCHEME);
        Attribute responseModeAttr = new Attribute("responseMode", "direct_post.jwt");
        Resource resource = new Resource(VP_CONFIG_RESOURCE_NAME, VP_CONFIG_RESOURCE_TYPE_NAME);
        resource.setAttributes(Arrays.asList(clientIdSchemeAttr, responseModeAttr));

        when(configurationManager.getResource(VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true))
                .thenReturn(resource);

        VPConfigService.TenantConfig config = configService.getConfig("example.com");

        Assert.assertEquals(config.getClientIdScheme(), VPConstants.DEFAULT_CLIENT_ID_SCHEME,
                "clientIdScheme should match the attribute value in the resource");
        Assert.assertEquals(config.getResponseMode(), "direct_post.jwt",
                "responseMode should match the attribute value in the resource");
    }

    @Test(priority = 4,
            description = "Test that getConfig wraps a ConfigurationManagementException "
                    + "in a VPAuthenticatorServerException",
            expectedExceptions = VPAuthenticatorServerException.class)
    public void testGetConfigThrowsOnConfigManagementException() throws Exception {

        ConfigurationManagementException exception = new ConfigurationManagementException(
                ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getMessage(),
                ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getCode());
        when(configurationManager.getResource(VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true))
                .thenThrow(exception);

        configService.getConfig("example.com");
    }

    @Test(priority = 5,
            description = "Test that setConfig calls replaceResource with the correct resource type and attributes")
    public void testSetConfigCallsReplaceResource() throws Exception {

        VPConfigService.TenantConfig config = new VPConfigService.TenantConfig();
        config.setClientIdScheme(VPConstants.DEFAULT_CLIENT_ID_SCHEME);
        config.setResponseMode(VPConstants.DEFAULT_RESPONSE_MODE);

        configService.setConfig(config, "example.com");

        verify(configurationManager).replaceResource(eq(VP_CONFIG_RESOURCE_TYPE_NAME), any(ResourceAdd.class));
    }

    @Test(priority = 6,
            description = "Test that setConfig wraps a ConfigurationManagementException "
                    + "in a VPAuthenticatorServerException",
            expectedExceptions = VPAuthenticatorServerException.class)
    public void testSetConfigThrowsOnConfigManagementException() throws Exception {

        ConfigurationManagementException exception = new ConfigurationManagementException(
                ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getMessage(),
                ERROR_CODE_RETRIEVE_RESOURCE_TYPE.getCode());
        when(configurationManager.replaceResource(eq(VP_CONFIG_RESOURCE_TYPE_NAME), any(ResourceAdd.class)))
                .thenThrow(exception);

        configService.setConfig(new VPConfigService.TenantConfig(), "example.com");
    }

    @Test(priority = 7,
            description = "Test that getConfigByTenantId resolves the tenant domain and delegates to getConfig")
    public void testGetConfigByTenantIdDelegatesToGetConfig() throws Exception {

        try (MockedStatic<IdentityTenantUtil> utilMock = Mockito.mockStatic(IdentityTenantUtil.class)) {
            utilMock.when(() -> IdentityTenantUtil.getTenantDomain(5)).thenReturn("tenant5.com");

            ConfigurationManagementException notFound = new ConfigurationManagementException(
                    ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                    ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
            when(configurationManager.getResource(VP_CONFIG_RESOURCE_TYPE_NAME, VP_CONFIG_RESOURCE_NAME, true))
                    .thenThrow(notFound);

            VPConfigService.TenantConfig config = configService.getConfigByTenantId(5);

            Assert.assertNotNull(config,
                    "getConfigByTenantId should return a non-null TenantConfig");
        }
    }
}
