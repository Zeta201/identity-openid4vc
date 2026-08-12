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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Utility class for fetching HTTP contents, removing duplicated HttpURLConnection logic.
 */
public class HttpClientUtil {

    private static final Log LOG = LogFactory.getLog(HttpClientUtil.class);

    private static final int HTTP_CONNECT_TIMEOUT = 5000;
    private static final int HTTP_READ_TIMEOUT = 5000;
    private static final int HTTP_OK = 200;
    private static final int MAX_RESPONSE_SIZE = 1024 * 1024;

    /**
     * Creates a utility class instance.
     *
     * <p>This constructor is intentionally private because this class exposes
     * only static utility methods.</p>
     */
    private HttpClientUtil() {

    }

    /**
         * Fetches a URL response body as a UTF-8 string.
         *
         * <p>Security checks include protocol validation, host validation, SSRF IP
         * filtering, redirect disabling, and response-size bounds enforcement.</p>
         *
         * @param urlString The URL to fetch
         * @param headers Optional request headers, or {@code null}
         * @return The response body when HTTP status is {@code 200}; otherwise {@code null}
         * @throws VerificationException If URL validation or network processing fails
     */
    public static String fetchContent(String urlString, Map<String, String> headers) 
            throws VerificationException {

        URI uri;
        try {
            uri = new java.net.URL(urlString).toURI();
        } catch (java.net.MalformedURLException | URISyntaxException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Invalid URL syntax or unhandled protocol: " + urlString, e);
        }

        // Only HTTPS is permitted. Plain HTTP is rejected because:
        // (a) credentials/metadata must not be fetched over an unencrypted channel, and
        // (b) HTTP allows the DNS-rebind TOCTOU gap to be exploited — a hostname that
        //     resolves to a public IP at validation time can be rebounded to an internal
        //     IP at connect time. HTTPS closes this via TLS certificate validation.
        if (!VerificationConstants.HTTPS_PREFIX.equalsIgnoreCase(uri.getScheme())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Only HTTPS is permitted for issuer metadata and JWKS fetches. Got: " + uri.getScheme());
        }

        if (uri.getHost() == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL, 
                    "Invalid host in URL: " + urlString);
        }

        // SSRF Protection: Validate the IP address
        validateIpAddress(uri.getHost());

        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) uri.toURL().openConnection();

            // SSRF Protection: Disable automatic redirects to prevent bypassing IP validation
            connection.setInstanceFollowRedirects(false);

            connection.setRequestMethod(VPConstants.HTTP.METHOD_GET);
            connection.setConnectTimeout(HTTP_CONNECT_TIMEOUT);
            connection.setReadTimeout(HTTP_READ_TIMEOUT);

            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    connection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }

            int httpStatusCode = connection.getResponseCode();
            if (httpStatusCode != HTTP_OK) {
                LOG.warn("Unexpected HTTP " + httpStatusCode + " fetching: " + urlString);
                return null;
            }

            try (InputStream inputStream = connection.getInputStream();
                 ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    responseBuffer.write(buffer, 0, bytesRead);
                    if (responseBuffer.size() > MAX_RESPONSE_SIZE) {
                        throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                                "Response body exceeds maximum allowed size of " + MAX_RESPONSE_SIZE + " bytes");
                    }
                }
                return responseBuffer.toString(StandardCharsets.UTF_8.name());
            }
        } catch (IOException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error fetching content from URL: " + urlString, e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
        * Fetches and parses JSON content from a URL.
        *
        * @param urlString The URL to fetch
        * @return The parsed {@link JsonObject}, or {@code null} for non-{@code 200} responses
        * @throws VerificationException If retrieval fails or the payload is not valid JSON
     */
    public static JsonObject fetchJson(String urlString) throws VerificationException {

        String fetchedContent = fetchContent(urlString, null);
        if (fetchedContent == null) {
            return null;
        }
        try {
            return JsonParser.parseString(fetchedContent).getAsJsonObject();
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to parse JSON content from URL: " + urlString, e);
        }
    }

    /**
        * Validates that the resolved host IP addresses are public and not internal.
        *
        * @param host The host name to resolve and validate
        * @throws VerificationException If host resolution fails or an internal/restricted
        *                               address is detected
     */
    private static void validateIpAddress(String host) throws VerificationException {

        try {
            InetAddress[] inetAddresses = InetAddress.getAllByName(host);
            for (InetAddress address : inetAddresses) {
                if (isRestrictedAddress(address)) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "SSRF Validation Failed: Target resolves to an internal or restricted IP address.");
                }
            }
        } catch (UnknownHostException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "SSRF Validation Failed: Unknown host.", e);
        }
    }

    /**
     * Checks if the given address is a restricted (non-global) address.
     *
     * @param addr The address to check
     * @return {@code true} if the address is restricted, {@code false} otherwise
     */
    private static boolean isRestrictedAddress(InetAddress address) {

        if (address == null) {
            return true;
        }

        if (address.isLoopbackAddress() ||
                address.isAnyLocalAddress() ||
                address.isLinkLocalAddress() ||
                address.isSiteLocalAddress() ||
                address.isMulticastAddress()) {
            return true;
        }

        // Check for IPv6 unique-local addresses (fc00::/7)
        byte[] addressBytes = address.getAddress();
        if (addressBytes.length == 16) { // IPv6
            return (addressBytes[0] & 0xFE) == 0xFC;
        }

        return false;
    }
}
