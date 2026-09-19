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

import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Utility class for fetching HTTP content.
 */
public class HttpClientUtil {

    private static final int HTTP_CONNECT_TIMEOUT = 5000;
    private static final int HTTP_READ_TIMEOUT = 5000;
    private static final int HTTP_OK = 200;
    private static final int MAX_RESPONSE_SIZE = 1024 * 1024;

    private HttpClientUtil() {

    }

    /**
     * Fetches a URL response body as a UTF-8 string.
     *
     * <p>Security checks include protocol validation, host validation, redirect
     * disabling, and response-size bounds enforcement.</p>
     *
     * @param urlString the URL to fetch
     * @return the response body when HTTP status is {@code 200}; otherwise {@code null}
     * @throws VerificationException if URL validation or network processing fails
     */
    public static String fetchContent(String urlString)
            throws VerificationException {

        URI uri;
        try {
            uri = new URL(urlString).toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.ISSUER_NOT_FOUND, e);
        }

        // Only HTTPS is permitted. Plain HTTP is rejected because
        // credentials/metadata must not be fetched over an unencrypted channel.
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.ISSUER_NOT_FOUND,
                    new IllegalStateException("JWKS URI must use HTTPS: " + urlString));
        }

        if (uri.getHost() == null) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.ISSUER_NOT_FOUND,
                    new IllegalStateException("JWKS URI has no host: " + urlString));
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofMillis(HTTP_READ_TIMEOUT));


        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(HTTP_CONNECT_TIMEOUT))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        try {
            HttpResponse<InputStream> response = client.send(requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofInputStream());

            int httpStatusCode = response.statusCode();
            if (httpStatusCode != HTTP_OK) {
                throw VerificationExceptionHandler.handleServerException(
                        VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        new IllegalStateException("JWKS endpoint returned HTTP " + httpStatusCode));
            }

            try (InputStream inputStream = response.body();
                 ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    responseBuffer.write(buffer, 0, bytesRead);
                    if (responseBuffer.size() > MAX_RESPONSE_SIZE) {
                        throw VerificationExceptionHandler.handleServerException(
                                VerificationErrorCode.INTERNAL_SERVER_ERROR,
                                new IllegalStateException("JWKS response exceeded maximum allowed size."));
                    }
                }
                return responseBuffer.toString(StandardCharsets.UTF_8);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.INTERNAL_SERVER_ERROR, e);
        } catch (IOException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.INTERNAL_SERVER_ERROR, e);
        }
    }
}
