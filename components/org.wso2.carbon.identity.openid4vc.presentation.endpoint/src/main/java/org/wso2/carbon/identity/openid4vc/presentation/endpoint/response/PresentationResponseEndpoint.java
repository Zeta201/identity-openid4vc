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

package org.wso2.carbon.identity.openid4vc.presentation.endpoint.response;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.PresentationErrorResponse;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.factories.PresentationSessionServiceFactory;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.factories.VerificationServiceFactory;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.service.VerificationService;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * Wallet-facing endpoint that receives VP token submissions from the wallet.
 *
 * <p>Accepts both {@code direct_post} (plain fields: {@code vp_token}, {@code state}) and
 * {@code direct_post.jwt} (single {@code response} JWE parameter), delivered as
 * {@code application/x-www-form-urlencoded}.</p>
 *
 * <p>Per OpenID4VP Section 8.2, always responds HTTP 200 for parseable submissions.
 * Credential verification failures are recorded in the session and do not cause non-200
 * responses. Non-200 is returned only for protocol-level failures.</p>
 */
@Path("/responses")
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
@Produces(MediaType.APPLICATION_JSON)
public class PresentationResponseEndpoint {

    private static final Log LOG = LogFactory.getLog(PresentationResponseEndpoint.class);

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response handlePresentationSubmission(MultivaluedMap<String, String> formParams) {

        String tenantDomain = CommonUtil.resolveTenantDomain();
        PresentationSubmissionDTO presentationSubmission;
        try {
            presentationSubmission = PresentationSessionServiceFactory.getPresentationSessionService()
                    .parsePresentationSubmission(formParams, tenantDomain);
        } catch (PresentationCoreClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Presentation submission client error.", e);
            }
            String errorResponse = PresentationErrorResponse.builder()
                    .error(e.getErrorType())
                    .errorDescription(e.getMessage())
                    .build()
                    .toJson();
            return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
        } catch (PresentationCoreException e) {
            LOG.error("Server error processing Presentation submission.", e);
            String errorResponse = PresentationErrorResponse.builder()
                    .error("server_error")
                    .errorDescription("Internal server error.")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(errorResponse).build();
        }

        String requestId = presentationSubmission.getRequestId();

        if (StringUtils.isNotBlank(presentationSubmission.getError())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Wallet reported error for requestId: %s, error: %s",
                        requestId, presentationSubmission.getError()));
            }
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(requestId, presentationSubmission.getError(),
                                presentationSubmission.getErrorDescription(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for requestId: %s", requestId), ex);
            }
            return Response.ok("{}", MediaType.APPLICATION_JSON).build();
        }

        VerificationRequestDTO verificationRequest;
        try {
            verificationRequest = PresentationSessionServiceFactory.getPresentationSessionService()
                    .buildVerificationRequest(presentationSubmission, tenantDomain);
        } catch (PresentationCoreClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Presentation submission validation failed for requestId: %s", requestId), e);
            }
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(requestId, e.getErrorType(), e.getMessage(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for requestId: %s", requestId), ex);
            }
            String errorResponse = PresentationErrorResponse.builder()
                    .error(e.getErrorType())
                    .errorDescription(e.getMessage())
                    .build()
                    .toJson();
            return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
        } catch (PresentationCoreException e) {
            LOG.error(String.format("Server error building verification request for requestId: %s", requestId), e);
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(requestId,
                                PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getErrorType(),
                                PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getDescription(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for requestId: %s", requestId), ex);
            }
            String errorResponse = PresentationErrorResponse.builder()
                    .error("server_error")
                    .errorDescription("Internal server error.")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(errorResponse).build();
        }

        VerificationService verificationService = VerificationServiceFactory.getVerificationService();
        try {
            VerificationResponseDTO result = verificationService.verifyPresentation(verificationRequest);
            PresentationSessionServiceFactory.getPresentationSessionService()
                    .handleSessionVerified(requestId, result, tenantDomain);
        } catch (PresentationCoreException e) {
            LOG.error(String.format("Failed to mark session as verified for requestId: %s", requestId), e);
        } catch (VerificationClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Credential verification failed for requestId: %s", requestId), e);
            }
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(requestId,
                                PresentationCoreErrorCode.VERIFICATION_FAILED.getErrorType(),
                                e.getErrorCode().getDescription(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for requestId: %s", requestId), ex);
            }
        } catch (VerificationException e) {
            LOG.error(String.format("Unexpected error during verification for requestId: %s", requestId), e);
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(requestId,
                                PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getErrorType(),
                                PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getDescription(), tenantDomain);
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for requestId: %s", requestId), ex);
            }
        }
        return Response.ok("{}", MediaType.APPLICATION_JSON).build();
    }
}
