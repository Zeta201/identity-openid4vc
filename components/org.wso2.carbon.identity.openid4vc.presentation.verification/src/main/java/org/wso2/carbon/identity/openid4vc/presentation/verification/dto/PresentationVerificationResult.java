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

package org.wso2.carbon.identity.openid4vc.presentation.verification.dto;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Aggregated outcome of a VP presentation verification.
 * Carries the verified/failed decision, error messages, extracted subject claims,
 * and per-credential presentation metadata.
 */
public class PresentationVerificationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean isVerified;
    private String statusMessage;
    private List<String> errors;
    private Map<String, Object> verifiedClaims;
    private List<PresentationMetadata> credentialMetadataList;

    private PresentationVerificationResult(Builder builder) {

        this.isVerified = builder.isVerified;
        this.statusMessage = builder.statusMessage;
        this.errors = builder.errors != null ? new ArrayList<>(builder.errors) : new ArrayList<>();
        this.verifiedClaims = builder.verifiedClaims != null ? new HashMap<>(builder.verifiedClaims) : new HashMap<>();
        this.credentialMetadataList = builder.credentialMetadataList != null
                ? new ArrayList<>(builder.credentialMetadataList) : new ArrayList<>();
    }

    public boolean isVerified() {

        return isVerified;
    }

    public String getStatusMessage() {

        return statusMessage;
    }

    public List<String> getErrors() {

        return new ArrayList<>(errors);
    }

    public Map<String, Object> getVerifiedClaims() {

        return new HashMap<>(verifiedClaims);
    }

    public List<PresentationMetadata> getCredentialMetadataList() {

        return new ArrayList<>(credentialMetadataList);
    }

    /**
     * Builder class for PresentationVerificationResult.
     */
    public static class Builder {

        private boolean isVerified;
        private String statusMessage;
        private List<String> errors = new ArrayList<>();
        private Map<String, Object> verifiedClaims = new HashMap<>();
        private List<PresentationMetadata> credentialMetadataList = new ArrayList<>();

        public Builder isVerified(boolean isVerified) {

            this.isVerified = isVerified;
            return this;
        }

        public Builder statusMessage(String statusMessage) {

            this.statusMessage = statusMessage;
            return this;
        }

        public Builder errors(List<String> errors) {

            this.errors = errors != null ? new ArrayList<>(errors) : new ArrayList<>();
            return this;
        }

        public Builder addError(String error) {

            this.errors.add(error);
            return this;
        }

        public Builder verifiedClaims(Map<String, Object> verifiedClaims) {

            this.verifiedClaims = verifiedClaims != null ? new HashMap<>(verifiedClaims) : new HashMap<>();
            return this;
        }

        public Builder credentialMetadataList(List<PresentationMetadata> list) {

            this.credentialMetadataList = list != null ? new ArrayList<>(list) : new ArrayList<>();
            return this;
        }

        public PresentationVerificationResult build() {

            return new PresentationVerificationResult(this);
        }
    }
}
