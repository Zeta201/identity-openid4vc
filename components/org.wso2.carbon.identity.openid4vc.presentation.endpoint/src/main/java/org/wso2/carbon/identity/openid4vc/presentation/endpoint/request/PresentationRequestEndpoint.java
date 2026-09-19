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

package org.wso2.carbon.identity.openid4vc.presentation.endpoint.request;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreUtil;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.PresentationErrorResponse;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.factories.PresentationRequestServiceFactory;
import org.wso2.carbon.identity.openid4vc.presentation.endpoint.factories.PresentationSessionServiceFactory;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * Wallet-facing endpoint that serves the signed OpenID4VP authorization request JWT.
 * The wallet fetches this after scanning the QR code that embeds the {@code request_uri}.
 */
@Path("/requests")
@Produces("application/oauth-authz-req+jwt")
public class PresentationRequestEndpoint {

    private static final Log LOG = LogFactory.getLog(PresentationRequestEndpoint.class);
    private static final String CONTENT_TYPE_AUTHZ_REQ = "application/oauth-authz-req+jwt";

    @GET
    @Path("/{id}")
    @Produces(CONTENT_TYPE_AUTHZ_REQ)
    public Response getPresentationRequest(@PathParam("id") String id) {

        String tenantDomain = PresentationCoreUtil.resolveTenantDomain();
        try {
            String requestJwt = PresentationRequestServiceFactory.getPresentationRequestService()
                    .buildPresentationRequest(id, tenantDomain);
            return Response.ok(requestJwt, CONTENT_TYPE_AUTHZ_REQ).build();

        } catch (PresentationCoreClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Presentation request client error for id: %s", id), e);
            }
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(id, tenantDomain, e.getErrorType(), e.getMessage());
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for id: %s", id), ex);
            }
            String errorResponse = PresentationErrorResponse.builder()
                    .error(e.getErrorType())
                    .errorDescription(e.getMessage())
                    .build()
                    .toJson();
            return Response.status(Response.Status.NOT_FOUND).entity(errorResponse).build();
        } catch (PresentationCoreException e) {
            LOG.error(String.format("Server error serving presentation request for id: %s", id), e);
            try {
                PresentationSessionServiceFactory.getPresentationSessionService()
                        .handleSessionFailed(id, tenantDomain,
                                PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getErrorType(),
                                PresentationCoreErrorCode.INTERNAL_SERVER_ERROR.getDescription());
            } catch (PresentationCoreException ex) {
                LOG.error(String.format("Failed to mark session as failed for id: %s", id), ex);
            }
            String errorResponse = PresentationErrorResponse.builder()
                    .error("server_error")
                    .errorDescription("Internal server error.")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(errorResponse).build();
        }
    }
}
