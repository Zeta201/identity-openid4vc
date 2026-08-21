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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.template.management.service.PresentationDefinitionService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Test class for {@link VPDataHolder}.
 * Tests that each service can be set and cleared via the static holder methods.
 */
public class VPDataHolderTest {

    @Mock
    private RealmService realmService;
    @Mock
    private PresentationDefinitionService presentationDefinitionService;
    @Mock
    private VerificationService verificationService;
    @Mock
    private ApplicationManagementService applicationManagementService;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
    }

    @Test(priority = 1, description = "Test that RealmService can be set and cleared via VPDataHolder")
    public void testGetSetRealmService() {

        // Set the service and verify it is retrievable
        VPDataHolder.setRealmService(realmService);
        Assert.assertEquals(VPDataHolder.getRealmService(), realmService,
                "getRealmService should return the service that was set");

        // Clear the service and verify it returns null
        VPDataHolder.setRealmService(null);
        Assert.assertNull(VPDataHolder.getRealmService(),
                "getRealmService should return null after being cleared");
    }

    @Test(priority = 2, description = "Test that PresentationDefinitionService can be set and cleared via VPDataHolder")
    public void testGetSetPresentationDefinitionService() {

        // Set the service and verify it is retrievable
        VPDataHolder.setPresentationDefinitionService(presentationDefinitionService);
        Assert.assertEquals(VPDataHolder.getPresentationDefinitionService(), presentationDefinitionService,
                "getPresentationDefinitionService should return the service that was set");

        // Clear the service and verify it returns null
        VPDataHolder.setPresentationDefinitionService(null);
        Assert.assertNull(VPDataHolder.getPresentationDefinitionService(),
                "getPresentationDefinitionService should return null after being cleared");
    }

    @Test(priority = 3, description = "Test that VerificationService can be set and cleared via VPDataHolder")
    public void testGetSetVerificationService() {

        // Set the service and verify it is retrievable
        VPDataHolder.setVerificationService(verificationService);
        Assert.assertEquals(VPDataHolder.getVerificationService(), verificationService,
                "getVerificationService should return the service that was set");

        // Clear the service and verify it returns null
        VPDataHolder.setVerificationService(null);
        Assert.assertNull(VPDataHolder.getVerificationService(),
                "getVerificationService should return null after being cleared");
    }

    @Test(priority = 4, description = "Test that ApplicationManagementService can be set and cleared via VPDataHolder")
    public void testGetSetApplicationManagementService() {

        // Set the service and verify it is retrievable
        VPDataHolder.setApplicationManagementService(applicationManagementService);
        Assert.assertEquals(VPDataHolder.getApplicationManagementService(), applicationManagementService,
                "getApplicationManagementService should return the service that was set");

        // Clear the service and verify it returns null
        VPDataHolder.setApplicationManagementService(null);
        Assert.assertNull(VPDataHolder.getApplicationManagementService(),
                "getApplicationManagementService should return null after being cleared");
    }
}
