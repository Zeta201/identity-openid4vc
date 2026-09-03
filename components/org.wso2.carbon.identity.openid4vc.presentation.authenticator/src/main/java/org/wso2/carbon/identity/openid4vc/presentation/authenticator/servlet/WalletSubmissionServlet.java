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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.WalletSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.ServletResponseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * OSGi HTTP whiteboard servlet that receives the wallet's VP token submission at
 * {@code /openid4vp/v1/response}. Validates the submission and updates the VP flow session.
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "osgi.http.whiteboard.servlet.pattern=/openid4vp/v1/response",
        "osgi.http.whiteboard.servlet.name=OpenID4VPSubmission",
        "osgi.http.whiteboard.servlet.asyncSupported=true"
    }
)
public class WalletSubmissionServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(WalletSubmissionServlet.class);

    private static final Gson GSON = new GsonBuilder().create();

    // DCQL vp_token: keys are credential query IDs, values are JSON arrays of credential tokens.
    private static final Type VP_TOKEN_RAW_TYPE = new TypeToken<Map<String, Object>>() { }.getType();

    private static final int MAX_BODY_BYTES = 1024 * 1024;

    @Override
    public void init() throws ServletException {

        super.init();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (VPDataHolder.getVPFlowService() == null) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "OpenID4VP feature is not enabled.");
            return;
        }

        try {
            if (request.getContentLength() > MAX_BODY_BYTES) {
                LOG.warn("Wallet submission rejected: Content-Length=" + request.getContentLength()
                        + " bytes exceeds limit of " + MAX_BODY_BYTES + " bytes.");
                response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        "Request body exceeds maximum allowed size.");
                return;
            }

            WalletSubmission submission = parseWalletSubmission(request);
            VPDataHolder.getVPFlowService().processWalletResponse(submission);
            ServletResponseUtil.sendSuccess(response);

        } catch (VPAuthenticatorClientException e) {
            ServletResponseUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (VPAuthenticatorServerException e) {
            LOG.error("Server error processing VP submission.", e);
            ServletResponseUtil.sendError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e);
        } catch (RuntimeException e) {
            LOG.error("Unexpected error processing VP submission.", e);
            ServletResponseUtil.sendError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Internal server error.", e));
        }
    }

    /**
     * Parses the raw HTTP request into a {@link WalletSubmission}.
     * Handles three submission shapes:
     * <ul>
     *   <li>form-encoded with a JWE {@code response} parameter ({@code direct_post.jwt}) — raw token is stored
     *       in {@link WalletSubmission#setRawJwe(String)}; decryption is performed by the service</li>
     *   <li>form-encoded plain fields ({@code direct_post})</li>
     *   <li>JSON body, optionally with a JWE {@code response} field</li>
     * </ul>
     *
     * @param request the HTTP servlet request carrying the wallet response
     * @return the parsed {@link WalletSubmission}
     * @throws IOException                    if reading the request body fails
     * @throws VPAuthenticatorClientException if the body exceeds the size limit or is not valid JSON
     */
    private WalletSubmission parseWalletSubmission(HttpServletRequest request)
            throws IOException, VPAuthenticatorClientException {

        // Read body once; size cap applies regardless of content type.
        byte[] rawBody = request.getInputStream().readNBytes(MAX_BODY_BYTES + 1);
        if (rawBody.length > MAX_BODY_BYTES) {
            LOG.warn("Wallet submission rejected: body stream read exceeded limit of "
                    + MAX_BODY_BYTES + " bytes.");
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request body exceeds maximum allowed size.");
        }
        String bodyStr = new String(rawBody, StandardCharsets.UTF_8);

        if (bodyStr.stripLeading().startsWith("{")) {
            try {
                JsonObject jsonBody = JsonParser.parseString(bodyStr).getAsJsonObject();
                JsonElement responseElem = jsonBody.get(VPConstants.ResponseParams.RESPONSE);
                if (responseElem != null && responseElem.isJsonPrimitive()
                        && isJweToken(responseElem.getAsString())) {
                    WalletSubmission jweSubmission = new WalletSubmission();
                    jweSubmission.setRawJwe(responseElem.getAsString());
                    return jweSubmission;
                }
                return GSON.fromJson(jsonBody, WalletSubmission.class);
            } catch (JsonSyntaxException e) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "Failed to parse request body as JSON.");
            }
        }

        // Form-encoded body (application/x-www-form-urlencoded).
        Map<String, String> formParams = decodeFormBody(bodyStr);
        String responseParam = formParams.get(VPConstants.ResponseParams.RESPONSE);
        if (isJweToken(responseParam)) {
            WalletSubmission jweSubmission = new WalletSubmission();
            jweSubmission.setRawJwe(responseParam);
            return jweSubmission;
        }
        return parseFormParameters(formParams);
    }

    /**
     * Returns {@code true} if the given value has the five dot-separated parts characteristic
     * of a JWE compact serialisation.
     *
     * @param value the string to inspect; may be {@code null}
     * @return {@code true} if {@code value} looks like a JWE compact token
     */
    private static boolean isJweToken(String value) {

        return value != null && value.split("\\.").length == 5;
    }

    /**
     * Decodes an {@code application/x-www-form-urlencoded} body string into a name→value map.
     * Duplicate keys are last-write-wins. Malformed percent-encoding is replaced with the
     * literal replacement character rather than throwing.
     *
     * @param body the raw URL-encoded body string; may be blank
     * @return a mutable map of decoded parameter names to decoded values
     */
    private static Map<String, String> decodeFormBody(String body) {

        Map<String, String> params = new HashMap<>();
        if (StringUtils.isBlank(body)) {
            return params;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            params.put(name, value);
        }
        return params;
    }

    /**
     * Parses a wallet submission from a decoded {@code application/x-www-form-urlencoded} parameter map.
     *
     * @param formParams the decoded form parameter map
     * @return a populated {@link WalletSubmission}
     * @throws VPAuthenticatorClientException if the {@code vp_token} parameter is not valid JSON
     */
    private WalletSubmission parseFormParameters(Map<String, String> formParams)
            throws VPAuthenticatorClientException {

        WalletSubmission submission = new WalletSubmission();
        String rawVpToken = formParams.get(VPConstants.ResponseParams.VP_TOKEN);
        if (StringUtils.isNotBlank(rawVpToken)) {
            try {
                Map<String, Object> rawMap = GSON.fromJson(rawVpToken, VP_TOKEN_RAW_TYPE);
                submission.setCredentialTokens(VPAuthenticatorUtil.flattenVpTokenMap(rawMap));
            } catch (JsonSyntaxException e) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "vp_token is not a valid JSON object.");
            }
        }
        submission.setRequestId(formParams.get(VPConstants.ResponseParams.STATE));
        submission.setError(formParams.get(VPConstants.ResponseParams.ERROR));
        submission.setErrorDescription(formParams.get(VPConstants.ResponseParams.ERROR_DESCRIPTION));
        return submission;
    }
}
