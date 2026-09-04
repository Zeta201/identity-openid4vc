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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Utility class for fetching HTTP content with SSRF protection.
 */
public class HttpClientUtil {

    private static final Log LOG = LogFactory.getLog(HttpClientUtil.class);

    private static final int HTTP_CONNECT_TIMEOUT = 5000;
    private static final int HTTP_READ_TIMEOUT = 5000;
    private static final int HTTP_OK = 200;
    private static final int MAX_RESPONSE_SIZE = 1024 * 1024;

    private HttpClientUtil() {

    }

    /**
     * Fetches a URL response body as a UTF-8 string.
     *
     * <p>Security checks include protocol validation, host validation, SSRF IP
     * filtering, redirect disabling, and response-size bounds enforcement.</p>
     *
     * @param urlString the URL to fetch
     * @param headers optional request headers, or {@code null}
     * @return the response body when HTTP status is {@code 200}; otherwise {@code null}
     * @throws VerificationException if URL validation or network processing fails
     */
    public static String fetchContent(String urlString, Map<String, String> headers)
            throws VerificationException {

        URI uri;
        try {
            uri = new URL(urlString).toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "Invalid URL syntax or unhandled protocol: " + urlString, e);
        }

        // Only HTTPS is permitted. Plain HTTP is rejected because
        // credentials/metadata must not be fetched over an unencrypted channel.
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

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofMillis(HTTP_READ_TIMEOUT));

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(HTTP_CONNECT_TIMEOUT))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        try {
            HttpResponse<InputStream> response = client.send(requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofInputStream());

            int httpStatusCode = response.statusCode();
            if (httpStatusCode != HTTP_OK) {
                throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        "Remote endpoint returned HTTP " + httpStatusCode + " for: " + urlString);
            }

            try (InputStream inputStream = response.body();
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
                return responseBuffer.toString(StandardCharsets.UTF_8);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "HTTP request interrupted for URL: " + urlString, e);
        } catch (IOException e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Error fetching content from URL: " + urlString, e);
        }
    }

    /**
     * Validates that the resolved host IP addresses are public and not internal.
     *
     * @param host the host name to resolve and validate
     * @throws VerificationException if host resolution fails or an internal/restricted address is detected
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
     * @param address the address to check
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
