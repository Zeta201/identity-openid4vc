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

import java.util.Arrays;
import java.util.List;
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
     * Nested claim paths are looked up via {@link #getValueAtClaimPath(Map, List)}.
     */
    private void verifyRequiredClaims(Map<String, Object> subjectClaims,
            Credential credential) throws VerificationException {

        if (credential == null || CollectionUtils.isEmpty(credential.getClaims())) {
            return;
        }

        for (PresentationClaim claim : credential.getClaims()) {
            String claimPath = claim.getPath();
            if (claimPath == null || claimPath.isEmpty()) {
                continue;
            }
            List<String> path = Arrays.asList(claimPath.split("\\."));
            Object value = getValueAtClaimPath(subjectClaims, path);

            if (claim.isMandatory() && value == null) {
                throw VerificationExceptionHandler.handleClientException(
                        VerificationErrorCode.INVALID_VP_SUBMISSION);
            }
        }
    }

    /**
     * Resolves a path array against a claim map, supporting nested objects.
     * Returns {@code null} when any segment in the path is missing or not a Map.
     *
     * <p>Example: {@code ["address", "street_address"]} traverses
     * {@code subjectClaims["address"]["street_address"]}.</p>
     */
    @SuppressWarnings("unchecked")
    private static Object getValueAtClaimPath(Map<String, Object> subjectClaims, List<String> path) {

        if (CollectionUtils.isEmpty(path)) {
            return null;
        }
        Object currentNode = subjectClaims;
        for (String segment : path) {
            if (!(currentNode instanceof Map)) {
                return null;
            }
            currentNode = ((Map<String, Object>) currentNode).get(segment);
        }
        return currentNode;
    }
}
