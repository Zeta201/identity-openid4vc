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

package org.wso2.carbon.identity.openid4vc.presentation.verification.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl.VerificationServiceImpl;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.impl.JwksValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.impl.PemValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.impl.X5cValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.FormatVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.impl.SdJwtVcVerifier;

/**
 * Service component for the OID4VP presentation verification bundle.
 */
@Component(
        name = "openid4vc.presentation.verification.service.component",
        immediate = true
)
public class PresentationVerificationServiceComponent {

    private static final Log LOG = LogFactory.getLog(PresentationVerificationServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(VerificationService.class, new VerificationServiceImpl(), null);
            bundleContext.registerService(FormatVerifier.class, new SdJwtVcVerifier(), null);
            bundleContext.registerService(CredentialSignatureValidator.class, new JwksValidator(), null);
            bundleContext.registerService(CredentialSignatureValidator.class, new PemValidator(), null);
            bundleContext.registerService(CredentialSignatureValidator.class, new X5cValidator(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("OID4VP presentation verification component activated.");
            }
        } catch (Throwable throwable) {
            LOG.error("Error while activating PresentationVerificationServiceComponent", throwable);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("OID4VP presentation verification component deactivated.");
        }
    }

    @Reference(
            name = "openid4vc.presentation.verification.format.verifier",
            service = FormatVerifier.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeFormatVerifier"
    )
    protected void addFormatVerifier(FormatVerifier formatVerifier) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding the FormatVerifier Service: " + formatVerifier.getFormat());
        }
        PresentationVerificationDataHolder.getInstance().addFormatVerifier(formatVerifier);
    }

    protected void removeFormatVerifier(FormatVerifier formatVerifier) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing the FormatVerifier Service: " + formatVerifier.getFormat());
        }
        PresentationVerificationDataHolder.getInstance().removeFormatVerifier(formatVerifier);
    }

    @Reference(
            name = "openid4vc.presentation.verification.credential.signature.validator",
            service = CredentialSignatureValidator.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeCredentialSignatureValidator"
    )
    protected void addCredentialSignatureValidator(CredentialSignatureValidator validator) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding the CredentialSignatureValidator Service: " + validator.getValidatorType());
        }
        PresentationVerificationDataHolder.getInstance().addCredentialSignatureValidator(validator);
    }

    protected void removeCredentialSignatureValidator(CredentialSignatureValidator validator) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing the CredentialSignatureValidator Service: " + validator.getValidatorType());
        }
        PresentationVerificationDataHolder.getInstance().removeCredentialSignatureValidator(validator);
    }

}
