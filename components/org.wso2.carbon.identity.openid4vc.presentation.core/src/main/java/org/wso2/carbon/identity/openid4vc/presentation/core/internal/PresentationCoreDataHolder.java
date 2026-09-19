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

package org.wso2.carbon.identity.openid4vc.presentation.core.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationConfigMgtService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationSessionService;
import org.wso2.carbon.identity.openid4vc.template.management.PresentationDefinitionManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for VP presentation core component.
 */
public class PresentationCoreDataHolder {

    private static final PresentationCoreDataHolder instance = new PresentationCoreDataHolder();

    private PresentationSessionService vpSessionService;
    private PresentationConfigMgtService vpConfigService;
    private RealmService realmService;
    private ApplicationManagementService applicationManagementService;
    private PresentationDefinitionManager presentationDefinitionManager;
    private ConfigurationManager configurationManager;

    private PresentationCoreDataHolder() {

    }

    public static PresentationCoreDataHolder getInstance() {

        return instance;
    }

    public PresentationSessionService getVpSessionService() {

        return vpSessionService;
    }

    public void setVpSessionService(PresentationSessionService vpSessionService) {

        this.vpSessionService = vpSessionService;
    }

    public PresentationConfigMgtService getVpConfigService() {

        return vpConfigService;
    }

    public void setVpConfigService(PresentationConfigMgtService vpConfigService) {

        this.vpConfigService = vpConfigService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    public PresentationDefinitionManager getPresentationDefinitionManager() {

        return presentationDefinitionManager;
    }

    public void setPresentationDefinitionManager(PresentationDefinitionManager presentationDefinitionManager) {

        this.presentationDefinitionManager = presentationDefinitionManager;
    }

    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }
}
