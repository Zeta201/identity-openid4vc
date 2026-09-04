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

import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;

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

        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate("", "example.com", 30_000L));
    }

    @Test(priority = 2,
            description = "Test that initiate throws VPAuthenticatorClientException when definitionId is null")
    public void testInitiateNullDefinitionIdThrows() {

        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate(null, "example.com", 30_000L));
    }

    @Test(priority = 3,
            description = "Test that initiate throws VPAuthenticatorClientException when tenantDomain is blank")
    public void testInitiateBlankTenantDomainThrows() {

        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate("def-id", "", 30_000L));
    }

    @Test(priority = 4,
            description = "Test that initiate throws VPAuthenticatorClientException when tenantDomain is null")
    public void testInitiateNullTenantDomainThrows() {

        Assert.assertThrows(VPAuthenticatorClientException.class,
                () -> service.initiate("def-id", null, 30_000L));
    }

    @Test(priority = 5, description = "Test that initiate validation failure carries the INVALID_REQUEST error code")
    public void testInitiateValidationErrorCodeIsInvalidRequest() {

        try {
            service.initiate("", "example.com", 30_000L);
        } catch (VPAuthenticatorClientException e) {
            Assert.assertEquals(e.getCode(), VPAuthenticatorErrorCode.INVALID_REQUEST.getCode(),
                    "Validation error code should be INVALID_REQUEST");
        } catch (VPAuthenticatorException e) {
            throw new RuntimeException("Unexpected exception type", e);
        }
    }
}
