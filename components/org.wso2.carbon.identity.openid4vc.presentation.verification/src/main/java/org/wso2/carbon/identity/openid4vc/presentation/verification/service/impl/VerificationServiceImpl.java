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
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery.CredentialQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationVerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handlers.SdJwtVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handlers.Verifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Implementation of the {@link VerificationService} for OpenID4VC presentations.
 *
 * <p>Handles format-agnostic orchestration only: credential token extraction from the DCQL map,
 * verifier routing, and claim constraint enforcement. All format-specific logic (parsing,
 * signature validation, type enforcement, metadata extraction) lives in the format-specific
 * {@link Verifier} implementation.
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
    public PresentationVerificationResult verify(DcqlQuery query, int tenantId,
            Map<String, String> credentialTokens, String expectedNonce,
            String expectedAudience) throws VerificationException {

        PresentationVerificationResult.Builder resultBuilder = new PresentationVerificationResult.Builder();
        try {
            if (query == null) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                        "DCQL query is required.");
            }
            List<CredentialQuery> credentialQueries = query.getCredentials();
            if (credentialQueries.isEmpty()) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_VP_SUBMISSION,
                        "DCQL query has no credential entries.");
            }
            CredentialQuery credentialQuery = credentialQueries.getFirst();

            String credentialToken = extractCredentialToken(credentialTokens, credentialQuery.getId());

            Verifier verifier = resolveVerifier(credentialQuery.getFormat());
            CredentialVerificationContext verificationContext =
                    new CredentialVerificationContext(credentialToken, credentialQuery, tenantId,
                            expectedNonce, expectedAudience);

            CredentialVerificationResult output = verifier.verify(verificationContext);

            verifyRequiredClaimsForCredential(output.getSubjectClaims(), credentialQuery);

            return resultBuilder
                    .isVerified(true)
                    .verifiedClaims(output.getSubjectClaims())
                    .credentialMetadataList(Collections.singletonList(output.getMetadata()))
                    .statusMessage(VerificationConstants.STATUS_VERIFICATION_SUCCESS)
                    .build();

        } catch (VerificationServerException e) {
            LOG.error("Credential verification encountered a server error [" + e.getErrorCode().getCode() + "].", e);
            throw e;
        } catch (VerificationClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Credential verification failed [" + e.getErrorCode().getCode() + "].", e);
            }
            return resultBuilder
                    .isVerified(false)
                    .addError(e.getMessage())
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
     * enforcement. Nested claim paths are resolved via {@link #resolvePath(Map, List)}.
     */
    private void verifyRequiredClaimsForCredential(Map<String, Object> verifiedClaims,
            CredentialQuery credentialQuery) throws VerificationException {

        if (credentialQuery == null || CollectionUtils.isEmpty(credentialQuery.getClaims())) {
            return;
        }

        for (DcqlQuery.ClaimQuery claim : credentialQuery.getClaims()) {
            String rawPath = claim.getPath();
            if (rawPath == null || rawPath.isEmpty()) {
                continue;
            }
            List<String> path = Arrays.asList(rawPath.split("\\."));
            Object value = resolvePath(verifiedClaims, path);

            if (claim.isMandatory() && value == null) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                        "Required claim at path " + rawPath + " is missing from the presentation.");
            }
        }
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
