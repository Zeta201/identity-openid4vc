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

package org.wso2.carbon.identity.openid4vc.presentation.core.service;

import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionRespDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;

import java.util.List;
import java.util.Map;

/**
 * OSGi service for VP flow session management (standalone verification and self-registration flows).
 */
public interface PresentationSessionService {

    /**
     * Initiates a new VP flow session. A random request ID is generated internally
     * and returned via the initiation result.
     *
     * @param presentationDefinitionId the ID of the presentation definition to request
     * @param tenantDomain             the tenant domain for the request
     * @return initiation result containing the request ID, wallet URL, request URI, and expiry timestamp
     * @throws PresentationCoreException if inputs are blank, the presentation definition is not found,
     *                                  or the configuration lookup fails
     */
    PresentationRequestResponseDTO startPresentationSession(String presentationDefinitionId, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Initiates a new VP flow session for a presentation definition looked up by its human-readable
     * identifier. A random request ID is generated internally and returned
     * via the initiation result.
     *
     * @param presentationDefinitionIdentifier the identifier of the presentation definition to request
     * @param tenantDomain                     the tenant domain for the request
     * @return initiation result containing the request ID, wallet URL, request URI, and expiry timestamp
     * @throws PresentationCoreException if inputs are blank, the presentation definition is not found,
     *                                  or the configuration lookup fails
     */
    PresentationRequestResponseDTO startPresentationSessionByIdentifier(String presentationDefinitionIdentifier,
                                                                        String tenantDomain)
            throws PresentationCoreException;

    /**
     * Looks up a VP flow session by its transaction ID, scoped to the given tenant.
     *
     * @param requestId    the transaction ID of the VP session
     * @param tenantDomain the tenant domain of the caller
     * @return the session
     * @throws PresentationCoreException if the session is not found, has expired, belongs to a different
     *                                   tenant, or the database read fails
     */
    VPSession getPresentationSession(String requestId, String tenantDomain) throws PresentationCoreException;

    /**
     * Parses the wallet's form submission into a {@link PresentationSubmissionDTO}.
     *
     * <p>Handles both {@code direct_post} (plain form fields) and {@code direct_post.jwt}
     * (JWE-encrypted {@code response} parameter). Validates that the response mode matches
     * what was agreed in the original authorization request.
     *
     * <p>The returned DTO always contains a {@code requestId}. If the wallet reported an error,
     * {@code error} and {@code errorDescription} are populated and {@code credentialTokens} is
     * empty — the caller must call {@link #handleSessionFailed} and return HTTP 200 without
     * proceeding to verification.
     *
     * @param formParams   raw form parameters from the wallet submission
     * @param tenantDomain the tenant domain resolved from the request URL
     * @return the parsed submission
     * @throws PresentationCoreClientException if the request is malformed or the response mode is mismatched
     * @throws PresentationCoreException       if a server-side failure occurs during decryption or parsing
     */
    PresentationSubmissionDTO parsePresentationSubmission(Map<String, List<String>> formParams, String tenantDomain)
            throws PresentationCoreClientException, PresentationCoreException;

    /**
     * Validates the session state and builds a {@link VerificationRequestDTO} ready for the
     * verification pipeline.
     *
     * <p>Reads the session to resolve the expected credential definition, nonce, and audience.
     * Throws if the session is missing, inactive, or the submission does not contain a token
     * for the expected credential.
     *
     * @param submission   the parsed wallet submission from {@link #parsePresentationSubmission}
     * @param tenantDomain the tenant domain of the caller
     * @return a fully populated {@link VerificationRequestDTO}
     * @throws PresentationCoreClientException if the session is missing/inactive or a required token is absent
     * @throws PresentationCoreException       if a server-side failure occurs during session lookup
     */
    VerificationRequestDTO buildVerificationRequest(PresentationSubmissionDTO submission, String tenantDomain)
            throws PresentationCoreClientException, PresentationCoreException;

    /**
     * Transitions the VP session to {@code VERIFIED}, stores the verification result, and emits
     * an audit log event. No-ops silently if the session is no longer present.
     *
     * @param requestId            the VP session identifier
     * @param tenantDomain         the tenant domain of the caller
     * @param verificationResponse the outcome returned by the verification pipeline
     */
    void handleSessionVerified(String requestId, VerificationResponseDTO verificationResponse, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Transitions the VP session to {@code FAILED}, records the error details, and emits an
     * audit log event. No-ops silently if the session is no longer present.
     *
     * @param requestId        the VP session identifier
     * @param tenantDomain     the tenant domain of the caller
     * @param errorType        machine-readable error type
     * @param errorDescription human-readable description of the failure reason
     */
    void handleSessionFailed(String requestId, String errorType, String errorDescription, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Returns the current status of a VP session for polling without evicting it from the cache.
     * Safe to call repeatedly while the session is active.
     *
     * @param requestId    the VP session identifier
     * @param tenantDomain the tenant domain of the caller
     * @return the session status DTO, or {@code null} if no session exists for the given request ID
     * @throws PresentationCoreException if the session lookup fails
     */
    VerificationSessionStatusDTO getPresentationSessionStatus(String requestId, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Returns the terminal verification result (VERIFIED or FAILED) for a VP session, without
     * evicting it from the cache. Callers receive a clean {@link VerificationSessionRespDTO} instead
     * of a raw {@link VPSession}.
     *
     * @param requestId    the VP session identifier
     * @param tenantDomain the tenant domain of the caller
     * @return the result, or {@code null} if no session exists for the given request ID
     * @throws PresentationCoreException if the session is still {@code ACTIVE} or the session lookup fails
     */
    VerificationSessionRespDTO getPresentationSessionResult(String requestId, String tenantDomain)
            throws PresentationCoreException;

}

