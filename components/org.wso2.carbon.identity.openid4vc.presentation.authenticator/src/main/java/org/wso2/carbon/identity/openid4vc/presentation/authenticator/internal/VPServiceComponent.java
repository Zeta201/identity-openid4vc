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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.VPAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.executor.VPRegistrationExecutor;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.listener.VPIdPManagementListener;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPConfigServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPFlowServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi DS component for the VP authenticator bundle.
 */
@Component(name = "org.wso2.carbon.identity.openid4vc.presentation.authenticator.component", immediate = true)
public class VPServiceComponent {

    private static final Log LOG = LogFactory.getLog(VPServiceComponent.class);

    private ServiceRegistration<?> authenticatorRegistration;
    private ServiceRegistration<?> idpListenerRegistration;
    private ServiceRegistration<?> flowServiceRegistration;
    private ServiceRegistration<?> configServiceRegistration;
    private ServiceRegistration<?> executorRegistration;

    /**
     * Activates the VP authenticator bundle, registering the authenticator, IdP listener,
     * and (when the feature flag is enabled) the flow service, config service, and executor.
     *
     * @param context the OSGi component context
     */
    @Activate
    protected void activate(ComponentContext context) {

        try {
            authenticatorRegistration = context.getBundleContext().registerService(
                    ApplicationAuthenticator.class.getName(), new VPAuthenticator(), null);
            idpListenerRegistration = context.getBundleContext().registerService(
                    IdentityProviderMgtListener.class.getName(), new VPIdPManagementListener(), null);

            if (Boolean.parseBoolean(IdentityUtil.getProperty(OpenID4VPConstants.ConfigKeys.FEATURE_ENABLED))) {
                VPFlowServiceImpl vpFlowService = new VPFlowServiceImpl();
                VPDataHolder.setVPFlowService(vpFlowService);
                flowServiceRegistration = context.getBundleContext().registerService(
                        VPFlowService.class.getName(), vpFlowService, null);

                VPConfigServiceImpl configService = new VPConfigServiceImpl();
                VPDataHolder.setVPConfigService(configService);
                configServiceRegistration = context.getBundleContext().registerService(
                        VPConfigService.class.getName(), configService, null);

                executorRegistration = context.getBundleContext().registerService(
                        Executor.class.getName(),
                        new VPRegistrationExecutor(vpFlowService), null);
            }

        } catch (Throwable e) {
            LOG.error("Error activating OpenID4VP authenticator component.", e);
        }
    }

    /**
     * Deactivates the VP authenticator bundle, unregistering all previously registered OSGi services.
     *
     * @param context the OSGi component context
     */
    @Deactivate
    protected void deactivate(ComponentContext context) {

        unregister(executorRegistration);
        unregister(configServiceRegistration);
        unregister(flowServiceRegistration);
        unregister(idpListenerRegistration);
        unregister(authenticatorRegistration);
        LOG.info("OpenID4VP authenticator component deactivated.");
    }

    /**
     * Safely unregisters an OSGi service registration, tolerating the case where the
     * service has already been unregistered during bundle shutdown.
     *
     * @param serviceRegistration the registration to unregister; ignored if {@code null}
     */
    private static void unregister(ServiceRegistration<?> serviceRegistration) {

        if (serviceRegistration != null) {
            try {
                serviceRegistration.unregister();
            } catch (IllegalStateException e) {
                // Already unregistered — bundle is stopping; safe to ignore.
                LOG.debug("Service already unregistered during bundle shutdown.", e);
            }
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

        VPDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        VPDataHolder.setRealmService(null);
    }

    @Reference(
        name = "org.wso2.carbon.identity.application.mgt.ApplicationManagementService",
        service = ApplicationManagementService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        VPDataHolder.setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        VPDataHolder.setApplicationManagementService(null);
    }

    @Reference(
        name = "org.wso2.carbon.identity.organization.management.service.OrganizationManager",
        service = OrganizationManager.class,
        cardinality = ReferenceCardinality.OPTIONAL,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        VPDataHolder.setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        VPDataHolder.setOrganizationManager(null);
    }

    @Reference(
        name = "openid4vc.presentation.definition.service",
        service = PresentationDefinitionService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetPresentationDefinitionService"
    )
    protected void setPresentationDefinitionService(PresentationDefinitionService presentationDefinitionService) {

        VPDataHolder.setPresentationDefinitionService(presentationDefinitionService);
    }

    protected void unsetPresentationDefinitionService(PresentationDefinitionService presentationDefinitionService) {

        VPDataHolder.setPresentationDefinitionService(null);
    }

    @Reference(
        name = "openid4vc.verification.service",
        service = VerificationService.class,
        cardinality = ReferenceCardinality.MANDATORY,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetVerificationService"
    )
    protected void setVerificationService(VerificationService verificationService) {

        VPDataHolder.setVerificationService(verificationService);
    }

    protected void unsetVerificationService(VerificationService verificationService) {

        VPDataHolder.setVerificationService(null);
    }
}
