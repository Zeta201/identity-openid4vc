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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.internal.PresentationVerificationDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationExceptionHandler;
import org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.FormatVerifier;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationClaim;

import java.util.Map;

/**
 * Implementation of the {@link VerificationService} for OpenID4VC presentations.
 *
 * <p>Handles format-agnostic orchestration: verifier routing and claim constraint enforcement.
 * All format-specific logic lives in the format-specific {@link FormatVerifier} implementation.
 */
public class VerificationServiceImpl implements VerificationService {

    @Override
    public VerificationResponseDTO verifyPresentation(VerificationRequestDTO verificationRequest)
            throws VerificationException {

        Credential credential = verificationRequest.getCredential();
        FormatVerifier resolvedFormatHandler = resolveFormatHandler(credential.getFormat());
        VerificationResponseDTO verificationResponse = resolvedFormatHandler.verifyCredential(verificationRequest);
        verifyRequiredClaims(verificationResponse.getSubjectClaims(), credential);
        return verificationResponse;
    }

    private FormatVerifier resolveFormatHandler(String credentialFormat) throws VerificationClientException {

        return PresentationVerificationDataHolder.getInstance().getFormatVerifiers().stream()
                .filter(formatVerifier -> formatVerifier.getFormat().equals(credentialFormat))
                .findFirst()
                .orElseThrow(() -> VerificationExceptionHandler.handleClientException(
                        VerificationErrorCode.INVALID_VP_FORMAT));
    }

    /**
     * Enforces claim constraints using per-claim {@code mandatory} enforcement.
     */
    private void verifyRequiredClaims(Map<String, Object> subjectClaims,
            Credential credential) throws VerificationException {

        if (credential == null || CollectionUtils.isEmpty(credential.getClaims())) {
            return;
        }

        for (PresentationClaim claim : credential.getClaims()) {
            String path = claim.getPath();
            if (StringUtils.isBlank(path)) {
                continue;
            }
            Object value = subjectClaims.get(path);

            if (claim.isMandatory() && value == null) {
                throw VerificationExceptionHandler.handleClientException(
                        VerificationErrorCode.INVALID_VP_SUBMISSION);
            }
        }
    }
}
