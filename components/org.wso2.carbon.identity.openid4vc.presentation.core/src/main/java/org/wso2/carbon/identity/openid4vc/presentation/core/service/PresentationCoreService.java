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
 * This interface manages VP flow sessions and builds the OpenID4VP authorization request JWT.
 */
public interface PresentationCoreService {

    /**
     * Initiates a new VP flow session.
     *
     * @param presentationDefinitionId Presentation definition ID.
     * @param tenantDomain             Tenant domain.
     * @return Presentation request response DTO.
     * @throws PresentationCoreException If an error occurred while initiating the session.
     */
    PresentationRequestResponseDTO startPresentationSession(String presentationDefinitionId, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Initiates a new VP flow session for a presentation definition identifier.
     *
     * @param presentationDefinitionIdentifier Presentation definition identifier.
     * @param tenantDomain                     Tenant domain.
     * @return Presentation request response DTO.
     * @throws PresentationCoreException If an error occurred while initiating the session.
     */
    PresentationRequestResponseDTO startPresentationSessionByIdentifier(String presentationDefinitionIdentifier,
                                                                        String tenantDomain)
            throws PresentationCoreException;

    /**
     * Retrieves a VP flow session by its transaction ID.
     *
     * @param requestId    VP session request ID.
     * @param tenantDomain Tenant domain.
     * @return VP session.
     * @throws PresentationCoreException If an error occurred while retrieving the session.
     */
    VPSession getPresentationSession(String requestId, String tenantDomain) throws PresentationCoreException;

    /**
     * Parses the wallet's form submission into a presentation submission DTO.
     *
     * @param formParams   Form parameters from the wallet submission.
     * @param tenantDomain Tenant domain.
     * @return Presentation submission DTO.
     * @throws PresentationCoreClientException If the request is malformed or the response mode is mismatched.
     * @throws PresentationCoreException       If an error occurred while parsing the submission.
     */
    PresentationSubmissionDTO parsePresentationSubmission(Map<String, List<String>> formParams, String tenantDomain)
            throws PresentationCoreClientException, PresentationCoreException;

    /**
     * Builds a verification request from the parsed wallet submission.
     *
     * @param submission   Parsed wallet submission.
     * @param tenantDomain Tenant domain.
     * @return Verification request DTO.
     * @throws PresentationCoreClientException If the session is missing, inactive, or a required token is absent.
     * @throws PresentationCoreException       If an error occurred while building the request.
     */
    VerificationRequestDTO buildVerificationRequest(PresentationSubmissionDTO submission, String tenantDomain)
            throws PresentationCoreClientException, PresentationCoreException;

    /**
     * Transitions the VP session to verified and stores the verification result.
     *
     * @param requestId            VP session request ID.
     * @param verificationResponse Verification response.
     * @param tenantDomain         Tenant domain.
     * @throws PresentationCoreException If an error occurred while updating the session.
     */
    void handleSessionVerified(String requestId, VerificationResponseDTO verificationResponse, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Transitions the VP session to failed and records the error details.
     *
     * @param requestId        VP session request ID.
     * @param errorType        Error type.
     * @param errorDescription Error description.
     * @param tenantDomain     Tenant domain.
     * @throws PresentationCoreException If an error occurred while updating the session.
     */
    void handleSessionFailed(String requestId, String errorType, String errorDescription, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Retrieves the current status of a VP session.
     *
     * @param requestId    VP session request ID.
     * @param tenantDomain Tenant domain.
     * @return VP session status DTO, or null if no session exists for the given request ID.
     * @throws PresentationCoreException If an error occurred while retrieving the status.
     */
    VerificationSessionStatusDTO getPresentationSessionStatus(String requestId, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Retrieves the terminal verification result of a VP session.
     *
     * @param requestId    VP session request ID.
     * @param tenantDomain Tenant domain.
     * @return Verification session result DTO, or null if no session exists for the given request ID.
     * @throws PresentationCoreException If the session is still active or the session lookup fails.
     */
    VerificationSessionRespDTO getPresentationSessionResult(String requestId, String tenantDomain)
            throws PresentationCoreException;

    /**
     * Generates the signed presentation request JWT for a VP flow session.
     *
     * @param requestId    VP session request ID.
     * @param tenantDomain Tenant domain resolved from the request URL.
     * @return Signed request JWT.
     * @throws PresentationCoreException If the session is not found or the JWT cannot be built.
     */
    String buildPresentationRequest(String requestId, String tenantDomain) throws PresentationCoreException;
}
