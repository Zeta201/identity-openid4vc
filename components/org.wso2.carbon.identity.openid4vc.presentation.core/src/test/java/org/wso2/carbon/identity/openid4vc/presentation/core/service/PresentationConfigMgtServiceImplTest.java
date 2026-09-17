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

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;
import org.wso2.carbon.identity.openid4vc.presentation.core.internal.PresentationCoreDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.impl.PresentationConfigMgtServiceImpl;

import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;

/**
 * Unit tests for {@link PresentationConfigMgtServiceImpl}.
 */
public class PresentationConfigMgtServiceImplTest {

    private static final String TENANT_DOMAIN = "carbon.super";

    private PresentationConfigMgtServiceImpl service;
    private ConfigurationManager mockConfigManager;

    @BeforeMethod
    public void setUp() {

        service = new PresentationConfigMgtServiceImpl();
        mockConfigManager = mock(ConfigurationManager.class);
        PresentationCoreDataHolder.getInstance().setConfigurationManager(mockConfigManager);
    }

    @Test(priority = 1, description = "Test getVPConfig returns config populated from resource attributes")
    public void testGetVPConfigSuccess() throws Exception {

        Resource resource = new Resource();
        Attribute clientIdAttr = new Attribute();
        clientIdAttr.setKey("clientIdScheme");
        clientIdAttr.setValue("x509_san_dns");
        Attribute responseModeAttr = new Attribute();
        responseModeAttr.setKey("responseMode");
        responseModeAttr.setValue("direct_post.jwt");
        resource.setAttributes(Arrays.asList(clientIdAttr, responseModeAttr));

        when(mockConfigManager.getResource(anyString(), anyString(), anyBoolean())).thenReturn(resource);

        VPTenantConfig result = service.getVPConfig(TENANT_DOMAIN);

        Assert.assertNotNull(result, "Config should not be null");
        Assert.assertEquals(result.getClientIdScheme(), "x509_san_dns",
                "clientIdScheme should be read from resource attribute");
        Assert.assertEquals(result.getResponseMode(), "direct_post.jwt",
                "responseMode should be read from resource attribute");
    }

    @Test(priority = 2, description = "Test getVPConfig returns empty config when resource not found")
    public void testGetVPConfigResourceNotFound() throws Exception {

        ConfigurationManagementException notFoundEx = new ConfigurationManagementException(
                ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getMessage(),
                ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode());
        when(mockConfigManager.getResource(anyString(), anyString(), anyBoolean())).thenThrow(notFoundEx);

        VPTenantConfig result = service.getVPConfig(TENANT_DOMAIN);

        Assert.assertNotNull(result, "Should return an empty config, not null");
        Assert.assertNull(result.getClientIdScheme(), "clientIdScheme should be null for empty config");
        Assert.assertNull(result.getResponseMode(), "responseMode should be null for empty config");
    }

    @Test(priority = 3, description = "Test getVPConfig returns empty config when resource exists but has no attributes")
    public void testGetVPConfigNullAttributes() throws Exception {

        Resource resource = new Resource();
        resource.setAttributes(null);
        when(mockConfigManager.getResource(anyString(), anyString(), anyBoolean())).thenReturn(resource);

        VPTenantConfig result = service.getVPConfig(TENANT_DOMAIN);

        Assert.assertNotNull(result, "Should return an empty config");
        Assert.assertNull(result.getClientIdScheme());
        Assert.assertNull(result.getResponseMode());
    }

    @Test(priority = 4, description = "Test getVPConfig wraps unexpected ConfigurationManagementException as server error")
    public void testGetVPConfigUnexpectedExceptionWrapped() throws Exception {

        ConfigurationManagementException unexpectedEx = new ConfigurationManagementException(
                "Unexpected error", "CONFIGM_99999");
        when(mockConfigManager.getResource(anyString(), anyString(), anyBoolean())).thenThrow(unexpectedEx);

        try {
            service.getVPConfig(TENANT_DOMAIN);
            Assert.fail("Expected PresentationCoreServerException");
        } catch (PresentationCoreServerException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.CONFIG_RETRIEVAL_ERROR.getCode(),
                    "Should wrap as CONFIG_RETRIEVAL_ERROR");
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreServerException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 5, description = "Test setVPConfig calls replaceResource with correct resource name")
    public void testSetVPConfigSuccess() throws Exception {

        VPTenantConfig config = new VPTenantConfig();
        config.setClientIdScheme("x509_san_dns");
        config.setResponseMode("direct_post");

        service.setVPConfig(config, TENANT_DOMAIN);

        verify(mockConfigManager).replaceResource(
                anyString(), any(ResourceAdd.class));
    }

    @Test(priority = 6, description = "Test setVPConfig wraps ConfigurationManagementException as server error")
    public void testSetVPConfigExceptionWrapped() throws Exception {

        when(mockConfigManager.replaceResource(anyString(), any(ResourceAdd.class)))
                .thenThrow(new ConfigurationManagementException("DB error", "CONFIGM_99999"));

        VPTenantConfig config = new VPTenantConfig();
        config.setClientIdScheme("x509_san_dns");

        try {
            service.setVPConfig(config, TENANT_DOMAIN);
            Assert.fail("Expected PresentationCoreServerException");
        } catch (PresentationCoreServerException e) {
            Assert.assertEquals(e.getCode(), PresentationCoreErrorCode.CONFIG_UPDATE_ERROR.getCode(),
                    "Should wrap as CONFIG_UPDATE_ERROR");
        } catch (PresentationCoreException e) {
            Assert.fail("Expected PresentationCoreServerException, got: " + e.getClass().getSimpleName());
        }
    }

    @Test(priority = 7, description = "Test setVPConfig with null field values does not add null attributes")
    public void testSetVPConfigNullFieldsNotPersisted() throws Exception {

        VPTenantConfig config = new VPTenantConfig();
        config.setClientIdScheme(null);
        config.setResponseMode(null);

        service.setVPConfig(config, TENANT_DOMAIN);

        // No exception thrown means replaceResource was called cleanly.
        verify(mockConfigManager).replaceResource(anyString(), any(ResourceAdd.class));
    }
}
