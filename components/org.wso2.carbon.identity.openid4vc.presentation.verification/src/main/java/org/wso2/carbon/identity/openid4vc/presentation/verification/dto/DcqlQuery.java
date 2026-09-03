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
import java.util.List;

/**
 * Immutable runtime representation of a DCQL query used during VP verification.
 *
 * <p>This is distinct from the stored {@code PresentationDefinition}: it carries only the fields
 * needed to execute a verification — no DB identifiers, display names, or tenant metadata.
 * Use {@code DcqlQueryMapper.from(PresentationDefinition)} to produce an instance.
 */
public class DcqlQuery implements Serializable {

    private static final long serialVersionUID = 1L;

    private final List<CredentialQuery> credentials;

    private DcqlQuery(Builder builder) {

        this.credentials = builder.credentials != null
                ? new ArrayList<>(builder.credentials) : new ArrayList<>();
    }

    public List<CredentialQuery> getCredentials() {

        return new ArrayList<>(credentials);
    }

    /**
     * Builder for {@link DcqlQuery}.
     */
    public static class Builder {

        private List<CredentialQuery> credentials;

        public Builder credentials(List<CredentialQuery> credentials) {

            this.credentials = credentials;
            return this;
        }

        public DcqlQuery build() {

            return new DcqlQuery(this);
        }
    }

    /**
     * A single credential entry in the DCQL {@code credentials} array.
     * Carries the query ID, expected format, expected vct, issuer trust config, and claim constraints.
     */
    public static class CredentialQuery implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String id;
        private final String format;
        private final String vct;
        private final List<IssuerConfig> issuerConfigs;
        private final List<ClaimQuery> claims;

        private CredentialQuery(Builder builder) {

            this.id = builder.id;
            this.format = builder.format;
            this.vct = builder.vct;
            this.issuerConfigs = builder.issuerConfigs != null
                    ? new ArrayList<>(builder.issuerConfigs) : null;
            this.claims = builder.claims != null
                    ? new ArrayList<>(builder.claims) : null;
        }

        public String getId() {

            return id;
        }

        public String getFormat() {

            return format;
        }

        public String getVct() {

            return vct;
        }

        public List<IssuerConfig> getIssuerConfigs() {

            return issuerConfigs != null ? new ArrayList<>(issuerConfigs) : null;
        }

        public List<ClaimQuery> getClaims() {

            return claims != null ? new ArrayList<>(claims) : null;
        }

        /**
         * Builder for {@link CredentialQuery}.
         */
        public static class Builder {

            private String id;
            private String format;
            private String vct;
            private List<IssuerConfig> issuerConfigs;
            private List<ClaimQuery> claims;

            public Builder id(String id) {

                this.id = id;
                return this;
            }

            public Builder format(String format) {

                this.format = format;
                return this;
            }

            public Builder vct(String vct) {

                this.vct = vct;
                return this;
            }

            public Builder issuerConfigs(List<IssuerConfig> issuerConfigs) {

                this.issuerConfigs = issuerConfigs;
                return this;
            }

            public Builder claims(List<ClaimQuery> claims) {

                this.claims = claims;
                return this;
            }

            public CredentialQuery build() {

                return new CredentialQuery(this);
            }
        }
    }

    /**
     * Issuer trust configuration — specifies how to resolve and trust the issuer's signing key.
     */
    public static class IssuerConfig implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String keySourceType;
        private final String issuerUrl;
        private final String keySource;
        private final List<String> akiValues;

        public IssuerConfig(String keySourceType, String issuerUrl, String keySource) {

            this(keySourceType, issuerUrl, keySource, null);
        }

        public IssuerConfig(String keySourceType, String issuerUrl, String keySource, List<String> akiValues) {

            this.keySourceType = keySourceType;
            this.issuerUrl = issuerUrl;
            this.keySource = keySource;
            this.akiValues = akiValues != null ? new ArrayList<>(akiValues) : null;
        }

        public String getKeySourceType() {

            return keySourceType;
        }

        public String getIssuerUrl() {

            return issuerUrl;
        }

        public String getKeySource() {

            return keySource;
        }

        public List<String> getAkiValues() {

            return akiValues != null ? new ArrayList<>(akiValues) : null;
        }
    }

    /**
     * A single claim constraint — the path that must be present and whether it is mandatory.
     */
    public static class ClaimQuery implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String path;
        private final boolean mandatory;

        public ClaimQuery(String path, boolean mandatory) {

            this.path = path;
            this.mandatory = mandatory;
        }

        public String getPath() {

            return path;
        }

        public boolean isMandatory() {

            return mandatory;
        }
    }
}
