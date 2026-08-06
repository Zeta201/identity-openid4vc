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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.servlet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;

import java.io.IOException;
import java.io.Serial;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR_CODE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_MESSAGE;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_STATUS;

/**
 * Servlet handling VP (Verifiable Presentation) authorization request operations.
 *
 * <p>Endpoints:</p>
 * <ul>
 *     <li>GET /oid4vp/v1/vp-request/{requestId} - Get authorization request JWT.</li>
 *     <li>GET /oid4vp/v1/vp-request/{requestId}/status - Get request status (with polling).</li>
 * </ul>
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/oid4vp/v1/vp-request/*",
        "osgi.http.whiteboard.servlet.name=OpenID4VPRequest",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPAuthorizationRequestServlet extends HttpServlet {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    @Override
    public void init() throws ServletException {

        super.init();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (VPDataHolder.getVPFlowService() == null) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "OpenID4VP feature is not enabled.");
            return;
        }

        String pathInfo = request.getPathInfo();

        if (StringUtils.isBlank(pathInfo) || "/".equals(pathInfo)) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request ID is required in path."));
            return;
        }

        String[] pathParts = pathInfo.split("/");

        if (pathParts.length < 2) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Invalid path format."));
            return;
        }
        
        String requestId = pathParts[1];
        boolean isStatusRequest = pathParts.length >= 3
                && OpenID4VPConstants.Endpoints.STATUS.equals(pathParts[2]);

        try {
            VPFlowSession session = VPDataHolder.getVPFlowService().getSession(requestId);
            if (session == null) {
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPFlowStatus.NOT_FOUND.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                                    "VP request not found: " + requestId));
                }
                return;
            }

            VPFlowStatus status = session.getStatus();

            if (status == VPFlowStatus.FAILED || status == VPFlowStatus.VERIFIED) {
                JsonObject statusResponse = new JsonObject();
                statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                statusResponse.addProperty(RESPONSE_STATUS, status.name());
                if (status == VPFlowStatus.FAILED && session.getFailureReason() != null) {
                    statusResponse.addProperty(RESPONSE_MESSAGE, session.getFailureReason());
                }
                sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                return;
            }

            if (status == VPFlowStatus.ACTIVE) {
                // Check if the session has expired by wall-clock time even though status is still ACTIVE.
                if (session.getExpiresAt() > 0 && System.currentTimeMillis() > session.getExpiresAt()) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPFlowStatus.EXPIRED.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                    return;
                }
                if (isStatusRequest) {
                    JsonObject statusResponse = new JsonObject();
                    statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                    statusResponse.addProperty(RESPONSE_STATUS, VPFlowStatus.ACTIVE.name());
                    sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
                } else {
                    serveAuthorizationRequestJwt(response, requestId);
                }
                return;
            }

            if (isStatusRequest) {
                JsonObject statusResponse = new JsonObject();
                statusResponse.addProperty(RESPONSE_REQUEST_ID, requestId);
                statusResponse.addProperty(RESPONSE_STATUS, status.name());
                sendJsonResponse(response, HttpServletResponse.SC_OK, statusResponse);
            } else {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                        "VP request is not active: " + status);
            }

        } catch (VPAuthenticatorClientException e) {
            if (VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED.getCode().equals(e.getCode())) {
                sendErrorResponse(response, HttpServletResponse.SC_GONE, e);
            } else {
                sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, e);
            }
        } catch (VPAuthenticatorException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (RuntimeException | IOException e) {
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Internal server error.", e));
        }
    }

    /**
     * Retrieves the signed authorization request JWT for the given request ID and writes it
     * to the response with the {@code application/oauth-authz-req+jwt} content type.
     *
     * @param response  the HTTP response to write the JWT to
     * @param requestId the transaction ID of the VP session
     * @throws VPAuthenticatorException if the session is not found or the JWT cannot be generated
     * @throws IOException              if writing to the response output stream fails
     */
    private void serveAuthorizationRequestJwt(HttpServletResponse response,
                                         String requestId) throws VPAuthenticatorException, IOException {

        String requestJwt = VPDataHolder.getVPFlowService().createAuthorizationRequestJwt(requestId);

        if (StringUtils.isBlank(requestJwt)) {
            throw new VPAuthenticatorServerException(
                VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                "Failed to generate request JWT for request: " + requestId);
        }

        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_OAUTH_AUTHZ_REQ);
        response.setStatus(HttpServletResponse.SC_OK);
        writeResponse(response, requestJwt);
    }

    /**
     * Writes a UTF-8 encoded string directly to the response output stream and flushes it.
     *
     * @param response the HTTP response to write to
     * @param content  the string content to write
     * @throws IOException if writing to the response output stream fails
     */
    private void writeResponse(HttpServletResponse response, String content) throws IOException {

        response.getOutputStream().write(content.getBytes(StandardCharsets.UTF_8));
        response.getOutputStream().flush();
    }

    /**
     * Serialises {@code data} to JSON and writes it to the response with the given HTTP status code
     * and a {@code application/json;charset=UTF-8} content type.
     *
     * @param response   the HTTP response to write to
     * @param statusCode the HTTP status code to set
     * @param data       the object to serialise as the response body
     * @throws IOException if writing to the response output stream fails
     */
    private void sendJsonResponse(HttpServletResponse response, int statusCode, Object data)
            throws IOException {

        response.setStatus(statusCode);
        response.setContentType(OpenID4VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);

        writeResponse(response, gson.toJson(data));
    }

    /**
     * Writes a JSON error body containing the error type, description, and error code,
     * then sends it with the given HTTP status code.
     *
     * @param response   the HTTP response to write to
     * @param statusCode the HTTP status code to set
     * @param exception  the exception whose error type, message, and code populate the response body
     * @throws IOException if writing to the response output stream fails
     */
    private void sendErrorResponse(HttpServletResponse response, int statusCode,
            VPAuthenticatorException exception)
            throws IOException {

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty(RESPONSE_ERROR, exception.getErrorType());
        errorObj.addProperty(RESPONSE_ERROR_DESCRIPTION, Encode.forJava(exception.getMessage()));
        errorObj.addProperty(RESPONSE_ERROR_CODE, exception.getCode());
        sendJsonResponse(response, statusCode, errorObj);
    }
}
