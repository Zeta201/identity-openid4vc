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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.ClaimConstraint;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handlers.SdJwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handlers.Verifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Implementation of the {@link VerificationService} for OpenID4VC presentations.
 *
 * <p>Handles format-agnostic orchestration only: credential token extraction from the DCQL map,
 * verifier routing, and claim constraint enforcement. All format-specific
 * logic (parsing, signature validation, type enforcement, metadata extraction) lives in the
 * format-specific {@link Verifier} implementation.
 */
@Component(
        name = "openid4vc.presentation.verification.service",
        immediate = true,
        service = VerificationService.class
)
public class VerificationServiceImpl implements VerificationService {

    private static final Log LOG = LogFactory.getLog(VerificationServiceImpl.class);

    private final List<Verifier> verifiers;

    public VerificationServiceImpl() {

        this.verifiers = List.of(new SdJwtVerifier());
    }

    @Override
    public VerificationResult verify(PresentationDefinition presentationDefinition, int tenantId,
                                      Map<String, String> credentialTokens, String expectedNonce,
                                      String expectedAudience)
            throws VerificationException {

        VerificationResult.Builder resultBuilder = new VerificationResult.Builder();
        try {
            if (presentationDefinition == null) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                        "Presentation definition is required.");
            }
            List<RequestedCredential> requestedCredentials = presentationDefinition.getRequestedCredentials();
            if (requestedCredentials == null || requestedCredentials.isEmpty()) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                        "Presentation definition has no requested credential.");
            }
            RequestedCredential requestedCredential = requestedCredentials.getFirst();

            String credentialToken = extractCredentialToken(credentialTokens, requestedCredential.getCredentialId());

            Verifier verifier = resolveVerifier(requestedCredential.getFormat());
            CredentialVerificationContext verificationContext =
                    new CredentialVerificationContext(credentialToken, requestedCredential, tenantId,
                            expectedNonce, expectedAudience);

            PresentationMetadata metadata = verifier.verify(verificationContext);

            verifyRequiredClaimsForCredential(metadata.getCredentialClaims(), requestedCredential);

            return resultBuilder
                    .isVerified(true)
                    .verifiedClaims(metadata.getCredentialClaims())
                    .credentialMetadataList(Collections.singletonList(metadata))
                    .statusMessage(VerificationConstants.STATUS_VERIFICATION_SUCCESS)
                    .build();

        } catch (VerificationClientException e) {
            return resultBuilder.isVerified(false)
                                .addError(e.getErrorCode().getCode() + ": " + e.getMessage())
                                .statusMessage(VerificationConstants.STATUS_VERIFICATION_FAILED)
                                .build();
        }
    }

    private String extractCredentialToken(Map<String, String> credentialTokens, String credentialId)
            throws VerificationClientException {

        if (credentialTokens == null || credentialTokens.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "vp_token contains no credential entries.");
        }
        String credentialToken = credentialTokens.get(credentialId);
        if (StringUtils.isBlank(credentialToken)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                    "vp_token does not contain the requested credential '" + credentialId + "'.");
        }
        return credentialToken;
    }

    private Verifier resolveVerifier(String format) throws VerificationClientException {

        return verifiers.stream()
                .filter(v -> v.getFormat().equals(format))
                .findFirst()
                .orElseThrow(() -> new VerificationClientException(VerificationErrorCode.INVALID_VP_FORMAT,
                        "No verifier found for format: " + format));
    }

    /**
     * Enforces claim constraints for a single credential using per-claim {@code mandatory}
     * and {@code allowedValues} enforcement. Nested claim paths are resolved via
     * {@link #resolvePath(Map, List)}.
     */
    private void verifyRequiredClaimsForCredential(Map<String, Object> verifiedClaims,
                                                    RequestedCredential requestedCredential)
            throws VerificationException {

        if (requestedCredential == null || CollectionUtils.isEmpty(requestedCredential.getClaims())) {
            return;
        }

        for (ClaimConstraint constraint : requestedCredential.getClaims()) {
            List<String> path = effectivePath(constraint);
            if (path.isEmpty()) {
                continue;
            }
            Object value = resolvePath(verifiedClaims, path);

            if (constraint.isMandatory() && value == null) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                        "Required claim at path " + path + " is missing from the presentation.");
            }

            if (value != null && CollectionUtils.isNotEmpty(constraint.getAllowedValues())) {
                // allowedValues is only meaningful for scalar claims (String, Number, Boolean).
                // Map and List claims produce Java collection rendering via toString() which
                // never matches a configured string — skip the check and warn the operator.
                if (value instanceof java.util.Map || value instanceof java.util.List) {
                    LOG.warn("allowedValues constraint at path " + path
                            + " is not applicable to collection-valued claims; constraint skipped.");
                } else if (!constraint.getAllowedValues().contains(value.toString())) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "Credential does not meet the required constraints for path " + path + ".");
                }
            }
        }
    }

    private static List<String> effectivePath(ClaimConstraint constraint) {

        return constraint.getPath() != null ? constraint.getPath() : Collections.emptyList();
    }

    /**
     * Resolves a DCQL path array against a claim map, supporting nested objects.
     * Returns {@code null} when any segment in the path is missing or is not a Map.
     *
     * <p>Example: {@code ["address", "street_address"]} traverses
     * {@code claims["address"]["street_address"]}.</p>
     */
    @SuppressWarnings("unchecked")
    private static Object resolvePath(Map<String, Object> claims, List<String> path) {

        if (CollectionUtils.isEmpty(path)) {
            return null;
        }
        Object currentNode = claims;
        for (String segment : path) {
            if (!(currentNode instanceof Map)) {
                return null;
            }
            currentNode = ((Map<String, Object>) currentNode).get(segment);
        }
        return currentNode;
    }

}
