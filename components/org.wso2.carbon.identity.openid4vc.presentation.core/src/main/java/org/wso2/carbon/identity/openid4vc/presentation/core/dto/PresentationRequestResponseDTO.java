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

package org.wso2.carbon.identity.openid4vc.presentation.core.dto;

/**
 * Response DTO returned when a new VP presentation session is initiated.
 * Contains the information the caller needs to redirect the user's wallet and
 * later poll for the session outcome.
 */
public class PresentationRequestResponseDTO {

    /** Uniquely identifies this VP session; used as the {@code state} in the presentation request. */
    private String requestId;
    /** Deep-link URL passed to the wallet to trigger the presentation flow. */
    private String walletUrl;
    /** {@code request_uri} the wallet fetches to retrieve the signed presentation request object. */
    private String requestUri;
    /** {@code client_id} embedded in the presentation request, identifying this server to the wallet. */
    private String clientId;
    /** Unix timestamp (milliseconds) after which the session is considered expired. */
    private long expiresAt;

    public PresentationRequestResponseDTO(String requestId, String walletUrl, String requestUri,
            String clientId, long expiresAt) {

        this.requestId = requestId;
        this.walletUrl = walletUrl;
        this.requestUri = requestUri;
        this.clientId = clientId;
        this.expiresAt = expiresAt;
    }

    public String getRequestId() {

        return requestId;
    }

    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    public String getWalletUrl() {

        return walletUrl;
    }

    public void setWalletUrl(String walletUrl) {

        this.walletUrl = walletUrl;
    }

    public String getRequestUri() {

        return requestUri;
    }

    public void setRequestUri(String requestUri) {

        this.requestUri = requestUri;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public long getExpiresAt() {

        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {

        this.expiresAt = expiresAt;
    }
}
