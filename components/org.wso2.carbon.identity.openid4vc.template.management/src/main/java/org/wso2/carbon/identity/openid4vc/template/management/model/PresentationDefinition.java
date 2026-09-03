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

package org.wso2.carbon.identity.openid4vc.template.management.model;

import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing a Presentation Definition.
 * This defines the credential requirements for a Verifiable Presentation request.
 */
public class PresentationDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String definitionId;
    private Integer cursorKey;
    private String identifier;
    private String displayName;
    private String description;
    private int tenantId;
    private List<RequestedCredential> requestedCredentials;

    public PresentationDefinition() {

    }

    private PresentationDefinition(Builder builder) {

        this.definitionId = builder.definitionId;
        this.identifier = builder.identifier;
        this.displayName = builder.displayName;
        this.description = builder.description;
        this.tenantId = builder.tenantId;
        this.requestedCredentials = builder.requestedCredentials;
    }

    public String getDefinitionId() {

        return definitionId;
    }

    public void setDefinitionId(String definitionId) {

        this.definitionId = definitionId;
    }

    public Integer getCursorKey() {

        return cursorKey;
    }

    public void setCursorKey(Integer cursorKey) {

        this.cursorKey = cursorKey;
    }

    public String getIdentifier() {

        return identifier;
    }

    public void setIdentifier(String identifier) {

        this.identifier = identifier;
    }

    public String getDisplayName() {

        return displayName;
    }

    public void setDisplayName(String displayName) {

        this.displayName = displayName;
    }

    public String getDescription() {

        return description;
    }

    public void setDescription(String description) {

        this.description = description;
    }

    public int getTenantId() {

        return tenantId;
    }

    public void setTenantId(int tenantId) {

        this.tenantId = tenantId;
    }

    public List<RequestedCredential> getRequestedCredentials() {

        return requestedCredentials != null ? new ArrayList<>(requestedCredentials) : null;
    }

    public void setRequestedCredentials(List<RequestedCredential> requestedCredentials) {

        this.requestedCredentials = requestedCredentials != null ? new ArrayList<>(requestedCredentials) : null;
    }

    /**
     * Builder class for PresentationDefinition.
     */
    public static class Builder {

        private String definitionId;
        private String identifier;
        private String displayName;
        private String description;
        private int tenantId;
        private List<RequestedCredential> requestedCredentials;

        public Builder definitionId(String definitionId) {

            this.definitionId = definitionId;
            return this;
        }

        public Builder identifier(String identifier) {

            this.identifier = identifier;
            return this;
        }

        public Builder displayName(String displayName) {

            this.displayName = displayName;
            return this;
        }

        public Builder description(String description) {

            this.description = description;
            return this;
        }

        public Builder tenantId(int tenantId) {

            this.tenantId = tenantId;
            return this;
        }

        public Builder requestedCredentials(List<RequestedCredential> requestedCredentials) {

            this.requestedCredentials = requestedCredentials != null ? new ArrayList<>(requestedCredentials) : null;
            return this;
        }

        public PresentationDefinition build() {

            return new PresentationDefinition(this);
        }
    }

    /**
     * Inner model class representing a single requested credential within a Presentation Definition.
     */
    public static class RequestedCredential implements Serializable {

        private static final long serialVersionUID = 1L;

        private String identifier;
        private String format = Constants.VC_SD_JWT_FORMAT;
        private String type;
        private List<IssuerConfig> issuerConfigs;
        private List<ClaimConstraint> claims;

        public RequestedCredential() {

        }

        public String getIdentifier() {

            return identifier;
        }

        public void setIdentifier(String identifier) {

            this.identifier = identifier;
        }

        public String getFormat() {

            return format;
        }

        public void setFormat(String format) {

            this.format = format;
        }

        public String getType() {

            return type;
        }

        public void setType(String type) {

            this.type = type;
        }

        public List<IssuerConfig> getIssuerConfigs() {

            return issuerConfigs != null ? new ArrayList<>(issuerConfigs) : null;
        }

        public void setIssuerConfigs(List<IssuerConfig> issuerConfigs) {

            this.issuerConfigs = issuerConfigs != null ? new ArrayList<>(issuerConfigs) : null;
        }

        public List<ClaimConstraint> getClaims() {

            return claims != null ? new ArrayList<>(claims) : null;
        }

        public void setClaims(List<ClaimConstraint> claims) {

            this.claims = claims != null ? new ArrayList<>(claims) : null;
        }

    }

    /**
     * Represents the issuer trust configuration for a single trusted issuer within a credential.
     * One row per trusted issuer; each row specifies one key resolution method.
     */
    public static class IssuerConfig implements Serializable {

        private static final long serialVersionUID = 1L;

        private String keySourceType;
        private String issuerUrl;
        private String keySource;

        public IssuerConfig() {

        }

        public String getKeySourceType() {

            return keySourceType;
        }

        public void setKeySourceType(String keySourceType) {

            this.keySourceType = keySourceType;
        }

        public String getIssuerUrl() {

            return issuerUrl;
        }

        public void setIssuerUrl(String issuerUrl) {

            this.issuerUrl = issuerUrl;
        }

        public String getKeySource() {

            return keySource;
        }

        public void setKeySource(String keySource) {

            this.keySource = keySource;
        }

    }

    /**
     * Represents a single claim constraint within a requested credential.
     */
    public static class ClaimConstraint implements Serializable {

        private static final long serialVersionUID = 1L;

        private String path;
        private boolean mandatory = true;

        public ClaimConstraint() {

        }

        public String getPath() {

            return path;
        }

        public void setPath(String path) {

            this.path = path;
        }

        public boolean isMandatory() {

            return mandatory;
        }

        public void setMandatory(boolean mandatory) {

            this.mandatory = mandatory;
        }

    }

    @Override
    public String toString() {

        return "PresentationDefinition{" +
                "definitionId='" + definitionId + '\'' +
                ", identifier='" + identifier + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }
}
