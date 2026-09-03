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

import com.google.gson.annotations.SerializedName;

import java.util.Map;

/**
 * Represents the inbound submission from the wallet at the VP response endpoint.
 * {@code credentialTokens} is the parsed DCQL vp_token — a map of credential query ID to credential token string.
 */
public class WalletSubmission {

    @SerializedName("state")
    private String requestId;

    @SerializedName("vp_token")
    private Map<String, String> credentialTokens;

    private String error;

    @SerializedName("error_description")
    private String errorDescription;

    /** Not serialized — tracks whether this submission arrived as a JWE (direct_post.jwt). */
    private transient boolean encrypted;

    /** Compact JWE token received in a {@code direct_post.jwt} response; null for plain {@code direct_post}. */
    private transient String rawJwe;

    public WalletSubmission() {

    }

    public String getRequestId() {

        return requestId;
    }

    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    public Map<String, String> getCredentialTokens() {

        return credentialTokens;
    }

    public void setCredentialTokens(Map<String, String> credentialTokens) {

        this.credentialTokens = credentialTokens;
    }

    public String getError() {

        return error;
    }

    public void setError(String error) {

        this.error = error;
    }

    public String getErrorDescription() {

        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {

        this.errorDescription = errorDescription;
    }

    public boolean isEncrypted() {

        return encrypted;
    }

    public void setEncrypted(boolean encrypted) {

        this.encrypted = encrypted;
    }

    public String getRawJwe() {

        return rawJwe;
    }

    public void setRawJwe(String rawJwe) {

        this.rawJwe = rawJwe;
    }

    @Override
    public String toString() {

        return "WalletSubmission{requestId='" + requestId + '\''
                + ", hasCredentialTokens=" + (credentialTokens != null && !credentialTokens.isEmpty())
                + '}';
    }
}
