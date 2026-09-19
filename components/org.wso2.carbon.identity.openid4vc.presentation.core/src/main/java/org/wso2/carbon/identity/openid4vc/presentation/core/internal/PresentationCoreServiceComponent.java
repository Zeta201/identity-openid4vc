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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.openid4vc.presentation.core.listener.VPIdPMgtListener;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationConfigMgtService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationSessionService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.impl.PresentationConfigMgtServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.impl.PresentationCoreServiceImpl;
import org.wso2.carbon.identity.openid4vc.template.management.PresentationDefinitionManager;
import org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi DS component for the VP presentation core bundle.
 */
@Component(
        name = "openid4vc.presentation.core.service.component",
        immediate = true
)
public class PresentationCoreServiceComponent {

    private static final Log LOG = LogFactory.getLog(PresentationCoreServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(IdentityProviderMgtListener.class, new VPIdPMgtListener(), null);

            PresentationConfigMgtServiceImpl configService = new PresentationConfigMgtServiceImpl();
            PresentationCoreDataHolder.getInstance().setVpConfigService(configService);
            bundleContext.registerService(PresentationConfigMgtService.class, configService, null);

            PresentationCoreServiceImpl vpSessionService = new PresentationCoreServiceImpl();
            PresentationCoreDataHolder.getInstance().setVpSessionService(vpSessionService);
            bundleContext.registerService(PresentationSessionService.class, vpSessionService, null);
            bundleContext.registerService(PresentationRequestService.class, vpSessionService, null);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OpenID4VP presentation core component activated.");
            }
        } catch (Throwable throwable) {
            LOG.error("Error while activating PresentationCoreServiceComponent", throwable);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("OpenID4VP presentation core component deactivated.");
        }
    }

    @Reference(
            name = "user.realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Realm Service.");
        }
        PresentationCoreDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Realm Service.");
        }
        PresentationCoreDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.application.mgt.ApplicationManagementService",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Application Management Service.");
        }
        PresentationCoreDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Application Management Service.");
        }
        PresentationCoreDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "openid4vc.presentation.definition.manager",
            service = PresentationDefinitionManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationDefinitionManager"
    )
    protected void setPresentationDefinitionManager(PresentationDefinitionManager presentationDefinitionManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Presentation Definition Manager.");
        }
        PresentationCoreDataHolder.getInstance().setPresentationDefinitionManager(presentationDefinitionManager);
    }

    protected void unsetPresentationDefinitionManager(PresentationDefinitionManager presentationDefinitionManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Presentation Definition Manager.");
        }
        PresentationCoreDataHolder.getInstance().setPresentationDefinitionManager(null);
    }

    @Reference(
            name = "identity.configuration.mgt.core.service",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationManager"
    )
    protected void setConfigurationManager(ConfigurationManager configurationManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Configuration Manager.");
        }
        PresentationCoreDataHolder.getInstance().setConfigurationManager(configurationManager);
    }

    protected void unsetConfigurationManager(ConfigurationManager configurationManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Configuration Manager.");
        }
        PresentationCoreDataHolder.getInstance().setConfigurationManager(null);
    }
}
