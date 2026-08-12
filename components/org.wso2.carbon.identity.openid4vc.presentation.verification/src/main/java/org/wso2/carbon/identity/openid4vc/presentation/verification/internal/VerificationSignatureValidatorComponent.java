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
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.impl.JwksUriSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.impl.PemSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.impl.X5cSignatureValidator;

/**
 * OSGi DS component that registers the X5C built-in {@link CredentialSignatureValidator}
 * and collects any externally contributed validators.
 *
 * <p>External bundles that wish to provide a custom validator must:
 * <ol>
 *   <li>Implement {@link CredentialSignatureValidator}.</li>
 *   <li>Register the implementation as an OSGi service via {@code bundleContext.registerService} or
 *       by annotating the class with {@code @Component(service = CredentialSignatureValidator.class)}.</li>
 * </ol>
 */
@Component(name = "openid4vc.verification.signature.validator.component", immediate = true)
public class VerificationSignatureValidatorComponent {

    private static final Log LOG = LogFactory.getLog(VerificationSignatureValidatorComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        VerificationServiceComponentHolder holder = VerificationServiceComponentHolder.getInstance();
        holder.addBuiltInValidator(new X5cSignatureValidator());
        holder.addBuiltInValidator(new JwksUriSignatureValidator());
        holder.addBuiltInValidator(new PemSignatureValidator());
        LOG.info("Credential signature validator component activated. "
                + "Built-in validators registered: X5C, JWKS_URI, PEM.");
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        VerificationServiceComponentHolder.getInstance().clearBuiltInValidators();
        LOG.info("Credential signature validator component deactivated.");
    }

    @Reference(
        name = "credential.signature.validator",
        service = CredentialSignatureValidator.class,
        cardinality = ReferenceCardinality.MULTIPLE,
        policy = ReferencePolicy.DYNAMIC,
        unbind = "unsetCredentialSignatureValidator"
    )
    protected void setCredentialSignatureValidator(CredentialSignatureValidator validator) {

        VerificationServiceComponentHolder.getInstance().addExternalValidator(validator);
        LOG.info("External credential signature validator registered: " + validator.getValidatorType());
    }

    protected void unsetCredentialSignatureValidator(CredentialSignatureValidator validator) {

        VerificationServiceComponentHolder.getInstance().removeExternalValidator(validator);
        LOG.info("External credential signature validator unregistered: " + validator.getValidatorType());
    }
}
