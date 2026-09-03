/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openid4vc.template.management.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceManager;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManager;
import org.wso2.carbon.identity.openid4vc.template.management.VCTemplateManagerImpl;
import org.wso2.carbon.identity.openid4vc.template.management.service.PresentationDefinitionService;
import org.wso2.carbon.identity.openid4vc.template.management.service.impl.PresentationDefinitionServiceImpl;

/**
 * Service component for the VC template management.
 */
@Component(
        name = "vc.template.mgt.service.component",
        immediate = true
)
public class VCTemplateManagementServiceComponent {

    private static final Log LOG = LogFactory.getLog(VCTemplateManagementServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleCtx = context.getBundleContext();
            bundleCtx.registerService(VCTemplateManager.class,
                    VCTemplateManagerImpl.getInstance(), null);
            bundleCtx.registerService(PresentationDefinitionService.class,
                    new PresentationDefinitionServiceImpl(), null);
            LOG.debug("VC template management bundle is activated");
        } catch (Throwable e) {
            LOG.error("Error while initializing VC template management component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        try {
            BundleContext bundleCtx = context.getBundleContext();
            bundleCtx.ungetService(bundleCtx.getServiceReference(VCTemplateManager.class));
            LOG.debug("VC template management bundle is deactivated");
        } catch (Throwable e) {
            LOG.error("Error while deactivating VC template management component.", e);
        }
    }

    @Reference(
            name = "api.resource.mgt.service.component",
            service = APIResourceManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAPIResourceManager")
    protected void setAPIResourceManager(APIResourceManager apiResourceManager) {

        VCTemplateManagementServiceDataHolder.getInstance().setAPIResourceManager(apiResourceManager);
        LOG.debug("APIResourceManager set in to bundle");
    }

    protected void unsetAPIResourceManager(APIResourceManager apiResourceManager) {

        VCTemplateManagementServiceDataHolder.getInstance().setAPIResourceManager(null);
        LOG.debug("APIResourceManager unset in to bundle");
    }

}
