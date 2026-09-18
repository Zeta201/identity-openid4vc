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

import java.util.HashMap;
import java.util.Map;

/**
 * Parsed result of a wallet's VP response submission.
 *
 * <p>Always carries a {@code requestId} so the caller can correlate the submission to its session.
 * When the wallet reported an error, {@code error} and {@code errorDescription} are set and
 * {@code credentialTokens} is {@code null} — the caller must call
 * {@code handleSessionFailed} instead of proceeding to verification.
 */
public class PresentationSubmissionDTO {

    /** VP session ID extracted from the {@code state} claim; correlates the response to its request. */
    private String requestId;
    /** Credential JWT tokens keyed by credential identifier. */
    private Map<String, String> credentialTokens;
    /** Error code reported by the wallet; non-null only on a wallet-side failure. */
    private String error;
    /** Description of the wallet-reported error; non-null only when {@code error} is set. */
    private String errorDescription;

    private PresentationSubmissionDTO(Builder builder) {

        this.requestId = builder.requestId;
        this.credentialTokens = builder.credentialTokens != null ? new HashMap<>(builder.credentialTokens) : null;
        this.error = builder.error;
        this.errorDescription = builder.errorDescription;
    }

    public String getRequestId() {

        return requestId;
    }

    public Map<String, String> getCredentialTokens() {

        return credentialTokens != null ? new HashMap<>(credentialTokens) : null;
    }

    public String getError() {

        return error;
    }

    public String getErrorDescription() {

        return errorDescription;
    }

    public static Builder builder() {

        return new Builder();
    }

    @Override
    public String toString() {

        return "PresentationSubmissionDTO{requestId='" + requestId + '\''
                + ", hasCredentialTokens=" + (credentialTokens != null && !credentialTokens.isEmpty())
                + '}';
    }

    /**
     * Builder for {@link PresentationSubmissionDTO}.
     */
    public static class Builder {

        private String requestId;
        private Map<String, String> credentialTokens;
        private String error;
        private String errorDescription;

        public Builder requestId(String requestId) {

            this.requestId = requestId;
            return this;
        }

        public Builder credentialTokens(Map<String, String> credentialTokens) {

            this.credentialTokens = credentialTokens;
            return this;
        }

        public Builder error(String error) {

            this.error = error;
            return this;
        }

        public Builder errorDescription(String errorDescription) {

            this.errorDescription = errorDescription;
            return this;
        }

        public PresentationSubmissionDTO build() {

            return new PresentationSubmissionDTO(this);
        }
    }
}
