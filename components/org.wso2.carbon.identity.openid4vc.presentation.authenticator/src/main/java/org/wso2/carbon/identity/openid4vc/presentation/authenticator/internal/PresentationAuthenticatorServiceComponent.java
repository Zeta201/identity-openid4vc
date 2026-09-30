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
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.PresentationAuthenticator;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.executor.PresentationExecutor;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationConfigMgtService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationCoreService;

/**
 * OSGi DS component for the VP authenticator bundle.
 */
@Component(
        name = "org.wso2.carbon.identity.openid4vc.presentation.authenticator.component",
        immediate = true
)
public class PresentationAuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(PresentationAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(ApplicationAuthenticator.class, new PresentationAuthenticator(), null);
            bundleContext.registerService(Executor.class, new PresentationExecutor(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("OpenID4VP authenticator component activated.");
            }
        } catch (Throwable throwable) {
            LOG.error("Error while activating PresentationAuthenticatorServiceComponent", throwable);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("OpenID4VP authenticator component deactivated.");
        }
    }

    @Reference(
            name = "openid4vc.presentation.core.vp.session.service",
            service = PresentationCoreService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationSessionService"
    )
    protected void setPresentationSessionService(PresentationCoreService presentationSessionService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Presentation Session Service.");
        }
        PresentationAuthenticatorDataHolder.getInstance().setPresentationSessionService(presentationSessionService);
    }

    protected void unsetPresentationSessionService(PresentationCoreService presentationSessionService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Presentation Session Service.");
        }
        PresentationAuthenticatorDataHolder.getInstance().setPresentationSessionService(null);
    }

    @Reference(
            name = "openid4vc.presentation.core.vp.config.service",
            service = PresentationConfigMgtService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPresentationConfigMgtService"
    )
    protected void setPresentationConfigMgtService(PresentationConfigMgtService presentationConfigMgtService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Presentation Config Management Service.");
        }
        PresentationAuthenticatorDataHolder.getInstance().setPresentationConfigMgtService(presentationConfigMgtService);
    }

    protected void unsetPresentationConfigMgtService(PresentationConfigMgtService presentationConfigMgtService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the Presentation Config Management Service.");
        }
        PresentationAuthenticatorDataHolder.getInstance().setPresentationConfigMgtService(null);
    }
}
