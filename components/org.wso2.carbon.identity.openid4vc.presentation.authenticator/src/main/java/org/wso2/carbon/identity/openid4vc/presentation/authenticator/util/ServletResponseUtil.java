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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_HEADER_VALUE_NOSNIFF;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS;

/**
 * Shared HTTP response helpers for VP flow servlets.
 */
public final class ServletResponseUtil {

    private static final Gson GSON = new GsonBuilder().create();

    private ServletResponseUtil() {}

    /**
     * Serializes {@code body} to JSON and writes it with the given status,
     * {@code application/json;charset=UTF-8} content type, {@code X-Content-Type-Options: nosniff},
     * and a {@code Content-Length} header.
     */
    public static void sendJson(HttpServletResponse response, int status, JsonObject body) throws IOException {

        byte[] payload = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        response.setStatus(status);
        response.setContentType(VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);
        response.setContentLength(payload.length);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }

    /**
     * Writes a standard {@code {"error": ..., "error_description": ...}} JSON body.
     * Gson serialization handles all control-character escaping in the exception fields.
     */
    public static void sendError(HttpServletResponse response, int status, VPAuthenticatorException e)
            throws IOException {

        JsonObject body = new JsonObject();
        body.addProperty(RESPONSE_ERROR, e.getErrorType());
        body.addProperty(RESPONSE_ERROR_DESCRIPTION, e.getMessage());
        sendJson(response, status, body);
    }

    /**
     * Writes an empty {@code {}} JSON body with HTTP 200 OK.
     */
    public static void sendSuccess(HttpServletResponse response) throws IOException {

        sendJson(response, HttpServletResponse.SC_OK, new JsonObject());
    }

    /**
     * Writes a UTF-8 string body with the given status and content type, including a
     * {@code Content-Length} header.
     */
    public static void sendBody(HttpServletResponse response, int status, String contentType, String body)
            throws IOException {

        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        response.setStatus(status);
        response.setContentType(contentType);
        response.setContentLength(payload.length);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }
}
