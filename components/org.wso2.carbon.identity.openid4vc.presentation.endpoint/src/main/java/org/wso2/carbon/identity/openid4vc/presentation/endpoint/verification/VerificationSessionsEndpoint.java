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

package org.wso2.carbon.identity.openid4vc.presentation.endpoint.verification;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.common.util.CommonUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionRespDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationSessionStatusDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.response.PresentationRequestResponse;
import org.wso2.carbon.identity.openid4vc.presentation.core.response.VerificationSessionResultResponse;
import org.wso2.carbon.identity.openid4vc.presentation.core.response.VerificationSessionStatusResponse;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.VerifierErrorResponse;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.factories.PresentationSessionServiceFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Client-facing REST endpoints for managing VP verification sessions.
 */
@Path("/verification-sessions")
@Produces(MediaType.APPLICATION_JSON)
public class VerificationSessionsEndpoint {

    private static final Log LOG = LogFactory.getLog(VerificationSessionsEndpoint.class);
    private static final Gson GSON = new Gson();

    /**
     * Starts a new VP verification session for the given presentation definition.
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     * @param body     JSON body containing {@code presentationDefinitionIdentifier}
     * @return 201 with {@code requestId}, {@code requestUri}, and {@code expiresAt}
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response startVerificationSession(@Context HttpServletRequest request,
                                             @Context HttpServletResponse response, String body) {

        String presentationDefinitionIdentifier;
        try {
            JsonObject json = GSON.fromJson(body, JsonObject.class);
            presentationDefinitionIdentifier = json != null && json.has("presentationDefinitionIdentifier")
                    ? json.get("presentationDefinitionIdentifier").getAsString() : null;
        } catch (Exception e) {
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.INVALID_REQUEST.getCode())
                    .message(PresentationCoreErrorCode.INVALID_REQUEST.getMessage())
                    .description("Request body must be valid JSON.")
                    .build()
                    .toJson();
            return Response.status(Response.Status.BAD_REQUEST).entity(error).build();
        }

        if (StringUtils.isBlank(presentationDefinitionIdentifier)) {
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.INVALID_REQUEST.getCode())
                    .message(PresentationCoreErrorCode.INVALID_REQUEST.getMessage())
                    .description("presentationDefinitionIdentifier is required.")
                    .build()
                    .toJson();
            return Response.status(Response.Status.BAD_REQUEST).entity(error).build();
        }

        String tenantDomain = CommonUtil.resolveTenantDomain();

        PresentationRequestResponseDTO initiateResponse;
        try {
            initiateResponse = PresentationSessionServiceFactory.getPresentationSessionService()
                    .startPresentationSession(presentationDefinitionIdentifier, tenantDomain);
        } catch (PresentationCoreClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error starting verification session.", e);
            }
            String error = VerifierErrorResponse.builder()
                    .code(e.getCode())
                    .message(e.getMessage())
                    .description(e.getDescription())
                    .build()
                    .toJson();
            return Response.status(Response.Status.BAD_REQUEST).entity(error).build();
        } catch (PresentationCoreException e) {
            LOG.error("Server error starting verification session.", e);
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getCode())
                    .message(PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getMessage())
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
        }
        return buildStartSessionResponse(initiateResponse);
    }

    /**
     * Returns the final result of a VP verification session once it has reached a terminal state.
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     * @param id       the VP request ID
     * @return the session result containing status and, on failure, the error details
     */
    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVerificationResult(@Context HttpServletRequest request,
                                          @Context HttpServletResponse response,
                                          @PathParam("id") String id) {

        String tenantDomain = CommonUtil.resolveTenantDomain();

        VerificationSessionRespDTO verificationResult;
        try {
            verificationResult = PresentationSessionServiceFactory.getPresentationSessionService()
                    .getPresentationSessionResult(id, tenantDomain);
        } catch (PresentationCoreClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Client error fetching session result for id: %s", id), e);
            }
            String error = VerifierErrorResponse.builder()
                    .code(e.getCode())
                    .message(e.getMessage())
                    .description(e.getDescription())
                    .build()
                    .toJson();
            Response.Status httpStatus = e.getErrorCode() == PresentationCoreErrorCode.VP_SESSION_PENDING
                    ? Response.Status.BAD_REQUEST
                    : Response.Status.NOT_FOUND;
            return Response.status(httpStatus).entity(error).build();
        } catch (PresentationCoreException e) {
            LOG.error(String.format("Server error fetching session result for id: %s", id), e);
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getCode())
                    .message(PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getMessage())
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
        }

        if (verificationResult == null) {
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode())
                    .message(PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getMessage())
                    .description(PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getDescription())
                    .build()
                    .toJson();
            return Response.status(Response.Status.NOT_FOUND).entity(error).build();
        }
        return buildVerificationResultResponse(verificationResult);
    }

    /**
     * Returns the current status of a VP verification session for polling.
     * Does not evict the session from cache, allowing repeated calls while the session is active.
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     * @param id       the VP request ID
     * @return the session state including status, expiry, and — when terminal — the error type
     */
    @GET
    @Path("/{id}/status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVerificationSessionStatus(@Context HttpServletRequest request,
                                                 @Context HttpServletResponse response,
                                                 @PathParam("id") String id) {

        String tenantDomain = CommonUtil.resolveTenantDomain();

        VerificationSessionStatusDTO sessionStatus;
        try {
            sessionStatus = PresentationSessionServiceFactory.getPresentationSessionService()
                    .getPresentationSessionStatus(id, tenantDomain);
        } catch (PresentationCoreClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Client error fetching verification session for id: %s", id), e);
            }
            String error = VerifierErrorResponse.builder()
                    .code(e.getCode())
                    .message(e.getMessage())
                    .description(e.getDescription())
                    .build()
                    .toJson();
            return Response.status(Response.Status.NOT_FOUND).entity(error).build();
        } catch (PresentationCoreException e) {
            LOG.error(String.format("Server error fetching verification session for id: %s", id), e);
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getCode())
                    .message(PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getMessage())
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
        }

        if (sessionStatus == null) {
            String error = VerifierErrorResponse.builder()
                    .code(PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getCode())
                    .message(PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getMessage())
                    .description(PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND.getDescription())
                    .build()
                    .toJson();
            return Response.status(Response.Status.NOT_FOUND).entity(error).build();
        }
        return buildSessionStatusResponse(sessionStatus);
    }

    private Response buildVerificationResultResponse(VerificationSessionRespDTO dto) {

        String payload = VerificationSessionResultResponse.builder()
                .status(dto.getStatus())
                .errorType(dto.getErrorType())
                .errorDescription(dto.getErrorDescription())
                .verificationResponse(dto.getVerificationResponse())
                .build()
                .toJson();
        return Response.ok(payload, MediaType.APPLICATION_JSON).build();
    }

    private Response buildStartSessionResponse(PresentationRequestResponseDTO dto) {

        String payload = PresentationRequestResponse.builder()
                .requestId(dto.getRequestId())
                .requestUri(dto.getRequestUri())
                .expiresAt(dto.getExpiresAt())
                .build()
                .toJson();
        return Response.status(Response.Status.CREATED)
                .entity(payload)
                .build();
    }

    private Response buildSessionStatusResponse(VerificationSessionStatusDTO dto) {

        String payload = VerificationSessionStatusResponse.builder()
                .requestId(dto.getRequestId())
                .status(dto.getStatus())
                .expiresAt(dto.getExpiresAt())
                .errorType(dto.getErrorType())
                .build()
                .toJson();
        return Response.ok(payload, MediaType.APPLICATION_JSON).build();
    }
}
