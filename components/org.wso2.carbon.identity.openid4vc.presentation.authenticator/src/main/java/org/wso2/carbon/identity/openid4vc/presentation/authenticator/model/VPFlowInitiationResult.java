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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

/**
 * Holds the outcome of a successfully initiated VP flow: the request ID,
 * the deep-link wallet URL, the request URI the wallet will fetch,
 * the client ID used to identify the verifier, and the request expiry timestamp.
 */
public class VPFlowInitiationResult {

    private final String requestId;
    private final String walletUrl;
    private final String requestUri;
    private final String clientId;
    private final long expiresAt;

    public VPFlowInitiationResult(String requestId, String walletUrl, String requestUri,
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

    public String getWalletUrl() {

        return walletUrl;
    }

    public String getRequestUri() {

        return requestUri;
    }

    public String getClientId() {

        return clientId;
    }

    public long getExpiresAt() {

        return expiresAt;
    }
}
