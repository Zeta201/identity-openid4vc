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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
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

/**
 * Servlet handling VP (Verifiable Presentation) authorization request operations.
 *
 * <p>Endpoint:</p>
 * <ul>
 *     <li>GET /openid4vp/v1/request/{requestId} - Get authorization request JWT (wallet-facing, public).</li>
 * </ul>
 *
 * <p>VP session status polling for the authentication portal browser session is handled by
 * {@link VPFlowStatusServlet} at {@code GET /openid4vp/v1/status?sessionDataKey={key}},
 * which validates the caller via the IS authentication context before returning status.</p>
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/openid4vp/v1/request/*",
        "osgi.http.whiteboard.servlet.name=OpenID4VPRequest",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPAuthorizationRequestServlet extends HttpServlet {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(VPAuthorizationRequestServlet.class);

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
        
        // Only the bare /{requestId} path is served here (wallet fetches the authorization JWT).
        // Status polling is handled by VPFlowStatusServlet at /openid4vp/v1/status.
        if (pathParts.length >= 3) {
            sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                    new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                            "Unknown path: " + pathInfo));
            return;
        }

        String requestId = pathParts[1];

        try {
            VPFlowSession session = VPDataHolder.getVPFlowService().getSession(requestId);
            if (session == null) {
                sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                                "VP request not found: " + requestId));
                return;
            }

            VPFlowStatus status = session.getStatus();

            if (status == VPFlowStatus.ACTIVE) {
                if (session.getExpiresAt() > 0 && System.currentTimeMillis() > session.getExpiresAt()) {
                    throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                            "VP request has expired: " + requestId);
                }
                serveAuthorizationRequestJwt(response, requestId);
                return;
            }

            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED,
                    "VP request is not active: " + status);

        } catch (VPAuthenticatorClientException e) {
            VPAuthenticatorUtil.markSessionFailed(requestId, e.getMessage());
            if (VPAuthenticatorErrorCode.VP_REQUEST_EXPIRED.getCode().equals(e.getCode())) {
                sendErrorResponse(response, HttpServletResponse.SC_GONE, e);
            } else {
                sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, e);
            }
        } catch (VPAuthenticatorException e) {
            VPAuthenticatorUtil.markSessionFailed(requestId, e.getMessage());
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (RuntimeException | IOException e) {
            VPAuthenticatorUtil.markSessionFailed(requestId, "An internal server error occurred.");
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
