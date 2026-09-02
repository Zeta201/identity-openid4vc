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
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;

import java.io.IOException;
import java.io.Serial;
import java.nio.charset.StandardCharsets;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_HEADER_VALUE_NOSNIFF;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_REQUEST_ID;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_STATUS;

/**
 * VP flow status endpoint used by the browser to poll for the result of a VP request.
 *
 * <p>Endpoint: {@code GET /openid4vp/v1/status?requestId={id}}</p>
 *
 * <p>Reads session state from
 * {@link org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache},
 * which is DB-backed and visible across all cluster nodes.</p>
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/openid4vp/v1/status",
        "osgi.http.whiteboard.servlet.name=OpenID4VPAuthStatus",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class VPFlowStatusServlet extends HttpServlet {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(VPFlowStatusServlet.class);

    private static final String PARAM_REQUEST_ID = "requestId";
    private static final String FIELD_MESSAGE = "message";
    private static final String FIELD_ERROR = "error";
    private static final String FIELD_ERROR_DESCRIPTION = "error_description";
    private static final String ERROR_INVALID_REQUEST = "invalid_request";

    private static final Gson GSON = new GsonBuilder().create();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String requestId = StringUtils.trimToNull(request.getParameter(PARAM_REQUEST_ID));
        if (StringUtils.isBlank(requestId)) {
            sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    ERROR_INVALID_REQUEST, "Missing requestId parameter.");
            return;
        }

        VPFlowSession session;
        try {
            session = VPSessionCache.getInstance().get(requestId);
        } catch (VPAuthenticatorServerException e) {
            LOG.error("Failed to retrieve VP session status for requestId: " + requestId, e);
            sendError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "server_error", "An internal error occurred while retrieving the session status.");
            return;
        }
        if (session == null) {
            sendStatus(response, requestId, VPFlowStatus.NOT_FOUND.name(), null);
            return;
        }

        VPFlowStatus status = session.getStatus();
        String failureReason = (status == VPFlowStatus.FAILED) ? session.getFailureReason() : null;
        sendStatus(response, requestId, status.name(), failureReason);
    }

    private void sendStatus(HttpServletResponse response, String requestId,
                            String status, String message) throws IOException {

        JsonObject body = new JsonObject();
        body.addProperty(RESPONSE_REQUEST_ID, requestId);
        body.addProperty(RESPONSE_STATUS, status);
        if (StringUtils.isNotBlank(message)) {
            body.addProperty(FIELD_MESSAGE, Encode.forJava(message));
        }
        sendJson(response, HttpServletResponse.SC_OK, body);
    }

    private void sendError(HttpServletResponse response, int status,
                           String error, String description) throws IOException {

        JsonObject body = new JsonObject();
        body.addProperty(FIELD_ERROR, error);
        body.addProperty(FIELD_ERROR_DESCRIPTION, description);
        sendJson(response, status, body);
    }

    private void sendJson(HttpServletResponse response, int status, JsonObject body) throws IOException {

        byte[] payload = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        response.setStatus(status);
        response.setContentType(VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);
        response.setContentLength(payload.length);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }
}
