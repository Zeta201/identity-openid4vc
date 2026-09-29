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

import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.FormatVerifier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Data holder for the OID4VP presentation verification component.
 */
public class PresentationVerificationDataHolder {

    private static final PresentationVerificationDataHolder instance = new PresentationVerificationDataHolder();

    private final List<FormatVerifier> formatVerifiers = new ArrayList<>();
    private final List<CredentialSignatureValidator> credentialSignatureValidators = new ArrayList<>();

    private PresentationVerificationDataHolder() {

    }

    public static PresentationVerificationDataHolder getInstance() {

        return instance;
    }

    public List<FormatVerifier> getFormatVerifiers() {

        return Collections.unmodifiableList(formatVerifiers);
    }

    public void addFormatVerifier(FormatVerifier verifier) {

        this.formatVerifiers.add(verifier);
    }

    public void removeFormatVerifier(FormatVerifier verifier) {

        this.formatVerifiers.remove(verifier);
    }

    public List<CredentialSignatureValidator> getCredentialSignatureValidators() {

        return Collections.unmodifiableList(credentialSignatureValidators);
    }

    public void addCredentialSignatureValidator(CredentialSignatureValidator validator) {

        this.credentialSignatureValidators.add(validator);
    }

    public void removeCredentialSignatureValidator(CredentialSignatureValidator validator) {

        this.credentialSignatureValidators.remove(validator);
    }

    public Optional<CredentialSignatureValidator> getCredentialSignatureValidator(String type) {

        return credentialSignatureValidators.stream()
                .filter(v -> v.getValidatorType().equals(type))
                .findFirst();
    }

}
