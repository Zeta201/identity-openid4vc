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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link VPServiceComponent}.
 * Tests OSGi lifecycle methods and service registration/unregistration.
 */
public class VPServiceComponentTest {

    private VPServiceComponent component;

    @Mock
    private ComponentContext componentContext;

    @Mock
    private BundleContext bundleContext;

    @Mock
    private PresentationDefinitionService presentationDefinitionService;

    private MockedStatic<VPDataHolder> mockedDataHolder;
    private MockedStatic<org.wso2.carbon.identity.core.util.IdentityUtil> mockedIdentityUtil;

    @BeforeMethod
    public void setUp() {

        System.setProperty("carbon.home", ".");
        MockitoAnnotations.openMocks(this);
        component = new VPServiceComponent();
        when(componentContext.getBundleContext()).thenReturn(bundleContext);
        mockedDataHolder = Mockito.mockStatic(VPDataHolder.class);
        mockedIdentityUtil = Mockito.mockStatic(org.wso2.carbon.identity.core.util.IdentityUtil.class);
        mockedIdentityUtil.when(() ->
                org.wso2.carbon.identity.core.util.IdentityUtil.getProperty("OpenID4VP.Enabled"))
                .thenReturn("true");
    }

    @AfterMethod
    public void tearDown() {

        if (mockedDataHolder != null) {
            mockedDataHolder.close();
        }
        if (mockedIdentityUtil != null) {
            mockedIdentityUtil.close();
        }
    }

    @Test(priority = 1, description = "Test that activate registers the authenticator and sets the VP flow service")
    public void testActivate() {

        // Execute test
        component.activate(componentContext);

        // Verify the authenticator is registered with the bundle context
        verify(bundleContext, atLeastOnce())
                .registerService(eq(ApplicationAuthenticator.class.getName()), any(), any());
        mockedDataHolder.verify(() -> VPDataHolder.setVPFlowService(any()), atLeastOnce());
    }

    @Test(priority = 2, description = "Test that deactivate completes without throwing an exception")
    public void testDeactivate() {

        // Execute test - should not throw
        component.deactivate(componentContext);
    }

    @Test(priority = 3,
            description = "Test that setPresentationDefinitionService wires and unwires the service correctly")
    public void testSetPresentationDefinitionService() {

        // Close the static mock so VPDataHolder uses its real implementation
        mockedDataHolder.close();
        mockedDataHolder = null;

        // Set the service and verify it is registered
        component.setPresentationDefinitionService(presentationDefinitionService);
        Assert.assertNotNull(VPDataHolder.getPresentationDefinitionService(),
                "PresentationDefinitionService should be set in VPDataHolder after registration");

        // Unset the service and verify it is cleared
        component.unsetPresentationDefinitionService(presentationDefinitionService);
        Assert.assertNull(VPDataHolder.getPresentationDefinitionService(),
                "PresentationDefinitionService should be null in VPDataHolder after unregistration");
    }
}
