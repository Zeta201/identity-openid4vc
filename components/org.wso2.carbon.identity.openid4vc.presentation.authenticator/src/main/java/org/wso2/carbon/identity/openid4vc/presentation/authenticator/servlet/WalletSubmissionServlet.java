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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.WalletSubmission;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.io.IOException;
import java.io.Serial;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_CONTENT_TYPE_CHARSET_UTF_8;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_HEADER_VALUE_NOSNIFF;
import static org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants.RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS;


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

    @Serial
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

        // Hoisted so every catch block can mark the right session as FAILED and stop the
        // browser's polling loop. Assigned as soon as the submission is parsed.
        String requestId = null;

        try {
            if (request.getContentLength() > MAX_BODY_BYTES) {
                LOG.warn("Wallet submission rejected: Content-Length=" + request.getContentLength()
                        + " bytes exceeds limit of " + MAX_BODY_BYTES + " bytes.");
                response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        "Request body exceeds maximum allowed size.");
                return;
            }

            WalletSubmission submission = parseWalletSubmission(request);

            // Capture requestId immediately so outer catch blocks can mark the session.
            requestId = submission.getRequestId();

            // Handle wallet error responses.
            if (StringUtils.isNotBlank(submission.getError())) {
                LOG.warn("Wallet sent error response: error=" + sanitize(submission.getError())
                        + ", error_description=" + sanitize(submission.getErrorDescription()));
                if (StringUtils.isNotBlank(requestId)) {
                    VPFlowSession errorSession = VPSessionCache.getInstance().get(requestId);
                    if (errorSession != null) {
                        errorSession.setStatus(VPFlowStatus.FAILED);
                        String walletReason = StringUtils.isNotBlank(submission.getErrorDescription())
                                ? submission.getErrorDescription()
                                : submission.getError();
                        errorSession.setFailureReason(sanitize(walletReason));
                        VPSessionCache.getInstance().put(requestId, errorSession);
                    }
                }
                sendSuccessResponse(response);
                return;
            }

            validateSubmission(submission);

            VPFlowSession session = VPSessionCache.getInstance().get(requestId);
            if (session == null) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "Invalid state parameter.");
            }

            enforceResponseModeCompliance(submission, session);

            try {
                VerificationResult verificationResult = VPDataHolder
                        .getVerificationService()
                        .verify(session.getPresentationDefinition(), session.getTenantId(),
                                submission.getCredentialTokens(), session.getNonce(),
                                session.getClientId());

                if (!verificationResult.isVerified()) {
                    String errorMsg = verificationResult.getErrors() != null
                            && !verificationResult.getErrors().isEmpty()
                            ? String.join(", ", verificationResult.getErrors())
                            : "VP verification failed.";
                    session.setStatus(VPFlowStatus.FAILED);
                    session.setFailureReason(errorMsg);
                    VPSessionCache.getInstance().put(requestId, session);
                    sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                            new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VERIFICATION_FAILED, errorMsg));
                    return;
                }

                session.setVerificationResult(verificationResult);
                session.setStatus(VPFlowStatus.VERIFIED);
                VPSessionCache.getInstance().put(requestId, session);

            } catch (VerificationException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("VP verification exception [" + e.getErrorCode().getCode() + "]: " + e.getMessage());
                }
                session.setStatus(VPFlowStatus.FAILED);
                session.setFailureReason(e.getMessage());
                VPSessionCache.getInstance().put(requestId, session);
                sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VERIFICATION_FAILED,
                                e.getMessage()));
                return;
            }

            sendSuccessResponse(response);

        } catch (VPAuthenticatorClientException e) {
            VPAuthenticatorUtil.markSessionFailed(requestId, sanitize(e.getMessage()));
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (VPAuthenticatorServerException e) {
            LOG.error("Server error processing VP submission.", e);
            VPAuthenticatorUtil.markSessionFailed(requestId, "An internal server error occurred during verification.");
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e);
        } catch (RuntimeException e) {
            LOG.error("Unexpected error processing VP submission.", e);
            VPAuthenticatorUtil.markSessionFailed(requestId, "An unexpected error occurred during verification.");
            sendErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                            "Internal server error.", e));
        }
    }

    /**
     * Parses the raw HTTP request into a {@link WalletSubmission}.
     * Handles three submission shapes:
     * <ul>
     *   <li>form-encoded with a JWE {@code response} parameter ({@code direct_post.jwt})</li>
     *   <li>form-encoded plain fields ({@code direct_post})</li>
     *   <li>JSON body, optionally with a JWE {@code response} field</li>
     * </ul>
     *
     * @param request the HTTP servlet request carrying the wallet response
     * @return the parsed {@link WalletSubmission}
     * @throws IOException                    if reading the request body fails
     * @throws VPAuthenticatorClientException if the body exceeds the size limit or is not valid JSON
     * @throws VPAuthenticatorServerException if JWE decryption fails
     */
    private WalletSubmission parseWalletSubmission(HttpServletRequest request)
            throws IOException, VPAuthenticatorClientException, VPAuthenticatorServerException {

        String contentType = StringUtils.defaultString(request.getContentType());

        if (contentType.startsWith("application/x-www-form-urlencoded")) {
            String responseParam = request.getParameter(VPConstants.ResponseParams.RESPONSE);
            if (isJweToken(responseParam)) {
                return decryptJweResponse(responseParam);
            }
            return parseFormParameters(request);
        }

        // JSON body (application/json) or unknown content type.
        byte[] rawBody = request.getInputStream().readNBytes(MAX_BODY_BYTES + 1);
        if (rawBody.length > MAX_BODY_BYTES) {
            LOG.warn("Wallet submission rejected: body stream read exceeded limit of "
                    + MAX_BODY_BYTES + " bytes (no Content-Length header was present).");
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Request body exceeds maximum allowed size.");
        }
        try {
            JsonObject jsonBody = JsonParser.parseString(
                    new String(rawBody, StandardCharsets.UTF_8)).getAsJsonObject();
            JsonElement responseElem = jsonBody.get(VPConstants.ResponseParams.RESPONSE);
            if (responseElem != null && responseElem.isJsonPrimitive()
                    && isJweToken(responseElem.getAsString())) {
                return decryptJweResponse(responseElem.getAsString());
            }
            return GSON.fromJson(jsonBody, WalletSubmission.class);
        } catch (JsonSyntaxException e) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Failed to parse request body as JSON.");
        }
    }

    /**
     * Flattens a DCQL vp_token map from {@code Map<String, Object>} to {@code Map<String, String>}.
     * Per DCQL spec, each value is a JSON array of credential tokens — we take index 0 (we request
     * exactly one credential per query, so the wallet returns exactly one).
     * If the value is already a plain string (legacy / non-DCQL wallets), it is used as-is.
     *
     * @param rawMap the raw vp_token map from the wallet submission
     * @return a flattened map of credential query ID to credential token string
     */
    private static Map<String, String> flattenVpTokenMap(Map<String, Object> rawMap) {

        Map<String, String> flattenedTokens = new HashMap<>();
        for (Map.Entry<String, Object> entry : rawMap.entrySet()) {
            Object tokenValue = entry.getValue();
            if (tokenValue instanceof List) {
                List<?> list = (List<?>) tokenValue;
                flattenedTokens.put(entry.getKey(), list.isEmpty() ? null : String.valueOf(list.get(0)));
            } else {
                flattenedTokens.put(entry.getKey(), tokenValue != null ? String.valueOf(tokenValue) : null);
            }
        }
        return flattenedTokens;
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
     * Parses a wallet submission from {@code application/x-www-form-urlencoded} form parameters.
     *
     * @param request the HTTP request carrying the form-encoded wallet response
     * @return a populated {@link WalletSubmission}
     * @throws VPAuthenticatorClientException if the {@code vp_token} parameter is not valid JSON
     */
    private WalletSubmission parseFormParameters(HttpServletRequest request) throws VPAuthenticatorClientException {

        WalletSubmission submission = new WalletSubmission();
        String rawVpToken = request.getParameter(VPConstants.ResponseParams.VP_TOKEN);
        if (StringUtils.isNotBlank(rawVpToken)) {
            try {
                Map<String, Object> rawMap = GSON.fromJson(rawVpToken, VP_TOKEN_RAW_TYPE);
                submission.setCredentialTokens(flattenVpTokenMap(rawMap));
            } catch (JsonSyntaxException e) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "vp_token is not a valid JSON object.");
            }
        }
        submission.setRequestId(request.getParameter(VPConstants.ResponseParams.STATE));
        submission.setError(request.getParameter(VPConstants.ResponseParams.ERROR));
        submission.setErrorDescription(request.getParameter(VPConstants.ResponseParams.ERROR_DESCRIPTION));
        return submission;
    }

    /**
     * Verifies that the wallet's submission matches the response mode configured for the VP session.
     * Throws if the session expects an encrypted response ({@code direct_post.jwt}) but received a
     * plaintext one, or vice versa.
     *
     * @param submission the wallet submission to check
     * @param session    the VP flow session carrying the configured response mode
     * @throws VPAuthenticatorClientException if the submission's encryption state does not match
     *                                         the configured response mode
     */
    private void enforceResponseModeCompliance(WalletSubmission submission, VPFlowSession session)
            throws VPAuthenticatorClientException {

        String configuredMode = session.getResponseMode();
        boolean expectEncrypted = Constants.RESPONSE_MODE_DIRECT_POST_JWT.equals(configuredMode);

        if (expectEncrypted && !submission.isEncrypted()) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Response mode mismatch: direct_post.jwt was configured but wallet sent an unencrypted response.");
        }
        if (!expectEncrypted && submission.isEncrypted()) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Response mode mismatch: direct_post was configured but wallet sent an encrypted JWE response.");
        }
    }

    /**
     * Validates that the wallet submission contains the mandatory {@code state} and {@code vp_token}
     * fields required to proceed with verification.
     *
     * @param submission the wallet submission to validate
     * @throws VPAuthenticatorClientException if the request ID or credential tokens are absent
     */
    private void validateSubmission(WalletSubmission submission) throws VPAuthenticatorClientException {

        if (StringUtils.isBlank(submission.getRequestId())) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Missing state parameter.");
        }
        if (submission.getCredentialTokens() == null || submission.getCredentialTokens().isEmpty()) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Missing vp_token.");
        }
    }

    /**
     * Decrypts a {@code direct_post.jwt} JWE compact token and maps the inner signed JWT claims
     * to a {@link WalletSubmission}.
     * Looks up the ephemeral EC private key from the VP session identified by the JWE {@code kid}.
     *
     * @param jweCompact the compact-serialised JWE received from the wallet
     * @return a {@link WalletSubmission} populated from the decrypted JWT claims
     * @throws VPAuthenticatorClientException if the JWE {@code kid} is missing, no session exists,
     *                                         or no ephemeral key is found for the session
     * @throws VPAuthenticatorServerException if decryption or JWT parsing fails
     */
    private WalletSubmission decryptJweResponse(String jweCompact)
            throws VPAuthenticatorClientException, VPAuthenticatorServerException {

        // Hoisted so the ParseException/JOSEException catch can mark the right session as FAILED.
        // The JWE header is not encrypted, so kid is readable even when decryption later fails.
        String requestId = null;
        try {
            JWEObject jweObject = JWEObject.parse(jweCompact);
            requestId = jweObject.getHeader().getKeyID();
            if (StringUtils.isBlank(requestId)) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "direct_post.jwt: missing kid in JWE header.");
            }

            VPFlowSession session = VPSessionCache.getInstance().get(requestId);
            if (session == null || StringUtils.isBlank(session.getEphemeralPrivateKeyJwk())) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "direct_post.jwt: no ephemeral key found for state: " + sanitize(requestId));
            }

            jweObject.decrypt(new ECDHDecrypter(ECKey.parse(session.getEphemeralPrivateKeyJwk())));

            // Some wallets (e.g. Inji) encrypt plain JSON claims directly without an inner signed JWT.
            SignedJWT innerJwt = jweObject.getPayload().toSignedJWT();
            JWTClaimsSet claims = (innerJwt != null)
                    ? innerJwt.getJWTClaimsSet()
                    : JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());

            WalletSubmission submission = new WalletSubmission();
            Map<String, Object> vpTokenMap = claims.getJSONObjectClaim(VPConstants.ResponseParams.VP_TOKEN);
            if (vpTokenMap != null) {
                submission.setCredentialTokens(flattenVpTokenMap(vpTokenMap));
            }
            String state = claims.getStringClaim(VPConstants.ResponseParams.STATE);
            submission.setRequestId(state != null ? state : requestId);
            submission.setError(claims.getStringClaim(VPConstants.ResponseParams.ERROR));
            submission.setErrorDescription(
                    claims.getStringClaim(VPConstants.ResponseParams.ERROR_DESCRIPTION));
            submission.setEncrypted(true);
            return submission;

        } catch (ParseException | JOSEException e) {
            // requestId is set when JWE header was parsed successfully but decryption/claim-parsing failed.
            VPAuthenticatorUtil.markSessionFailed(requestId, "Failed to decrypt wallet response.");
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to decrypt or parse direct_post.jwt JWE response.", e);
        }
    }

    /**
     * Strips or replaces characters that could enable log injection or XSS
     * (CR, LF, angle brackets, and quotes) with underscores.
     *
     * @param input the raw string to sanitize; may be {@code null}
     * @return the sanitized string, or an empty string if {@code input} is {@code null}
     */
    private String sanitize(String input) {

        if (input == null) {
            return "";
        }
        return input.replace('\r', '_').replace('\n', '_').replaceAll("[<>\"']", "_");
    }

    /**
     * Writes an empty JSON object ({@code {}}) to the response with HTTP 200 OK,
     * indicating that the wallet submission was accepted.
     *
     * @param response the HTTP response to write to
     * @throws IOException if writing to the response output stream fails
     */
    private void sendSuccessResponse(HttpServletResponse response) throws IOException {

        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
        response.getOutputStream().flush();
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

        response.setStatus(statusCode);
        response.setContentType(VPConstants.HTTP.CONTENT_TYPE_JSON + RESPONSE_CONTENT_TYPE_CHARSET_UTF_8);
        response.setHeader(RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS, RESPONSE_HEADER_VALUE_NOSNIFF);

        JsonObject errorObj = new JsonObject();
        errorObj.addProperty(RESPONSE_ERROR, sanitize(exception.getErrorType()));
        errorObj.addProperty(RESPONSE_ERROR_DESCRIPTION, sanitize(exception.getMessage()));

        byte[] payload = GSON.toJson(errorObj).getBytes(StandardCharsets.UTF_8);
        response.getOutputStream().write(payload);
        response.getOutputStream().flush();
    }
}
