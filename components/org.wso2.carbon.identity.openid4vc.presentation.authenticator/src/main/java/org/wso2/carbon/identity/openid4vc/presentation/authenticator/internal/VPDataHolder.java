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

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.template.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Data holder for the VP authenticator bundle.
 */
public class VPDataHolder {

    private static final AtomicReference<VPFlowService> VP_FLOW_SERVICE = new AtomicReference<>();
    private static final AtomicReference<PresentationDefinitionService> PRESENTATION_DEFINITION_SERVICE =
            new AtomicReference<>();
    private static final AtomicReference<VerificationService> VERIFICATION_SERVICE = new AtomicReference<>();
    private static final AtomicReference<VPConfigService> VP_CONFIG_SERVICE = new AtomicReference<>();
    private static final AtomicReference<RealmService> REALM_SERVICE = new AtomicReference<>();
    private static final AtomicReference<ApplicationManagementService> APPLICATION_MANAGEMENT_SERVICE =
            new AtomicReference<>();
    private static final AtomicReference<OrganizationManager> ORGANIZATION_MANAGER = new AtomicReference<>();
    private static final AtomicReference<ConfigurationManager> CONFIGURATION_MANAGER = new AtomicReference<>();

    private VPDataHolder() {

    }

    public static VPFlowService getVPFlowService() {

        return VP_FLOW_SERVICE.get();
    }

    public static void setVPFlowService(VPFlowService vpFlowService) {

        VP_FLOW_SERVICE.set(vpFlowService);
    }

    public static PresentationDefinitionService getPresentationDefinitionService() {

        return PRESENTATION_DEFINITION_SERVICE.get();
    }

    public static void setPresentationDefinitionService(PresentationDefinitionService presentationDefinitionService) {

        PRESENTATION_DEFINITION_SERVICE.set(presentationDefinitionService);
    }

    public static VerificationService getVerificationService() {

        return VERIFICATION_SERVICE.get();
    }

    public static void setVerificationService(VerificationService verificationService) {

        VERIFICATION_SERVICE.set(verificationService);
    }

    public static VPConfigService getVPConfigService() {

        return VP_CONFIG_SERVICE.get();
    }

    public static void setVPConfigService(VPConfigService configService) {

        VP_CONFIG_SERVICE.set(configService);
    }

    public static RealmService getRealmService() {

        return REALM_SERVICE.get();
    }

    public static void setRealmService(RealmService realmService) {

        REALM_SERVICE.set(realmService);
    }

    public static ApplicationManagementService getApplicationManagementService() {

        return APPLICATION_MANAGEMENT_SERVICE.get();
    }

    public static void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        APPLICATION_MANAGEMENT_SERVICE.set(applicationManagementService);
    }

    public static OrganizationManager getOrganizationManager() {

        return ORGANIZATION_MANAGER.get();
    }

    public static void setOrganizationManager(OrganizationManager organizationManager) {

        ORGANIZATION_MANAGER.set(organizationManager);
    }

    public static ConfigurationManager getConfigurationManager() {

        return CONFIGURATION_MANAGER.get();
    }

    public static void setConfigurationManager(ConfigurationManager configurationManager) {

        CONFIGURATION_MANAGER.set(configurationManager);
    }
}
