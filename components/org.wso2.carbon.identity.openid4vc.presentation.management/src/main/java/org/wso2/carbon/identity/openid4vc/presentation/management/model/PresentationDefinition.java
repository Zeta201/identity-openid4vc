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

package org.wso2.carbon.identity.openid4vc.presentation.management.model;

import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;

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
    private String name;
    private String description;
    private int tenantId;
    private List<RequestedCredential> requestedCredentials;

    public PresentationDefinition() {

    }

    private PresentationDefinition(Builder builder) {

        this.definitionId = builder.definitionId;
        this.name = builder.name;
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

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
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
        private String name;
        private String description;
        private int tenantId;
        private List<RequestedCredential> requestedCredentials;

        public Builder definitionId(String definitionId) {

            this.definitionId = definitionId;
            return this;
        }

        public Builder name(String name) {

            this.name = name;
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

        private String credentialId;
        private String format = Constants.VC_SD_JWT_FORMAT;
        private String type;
        private boolean enforceTrustedIssuer = false;
        private List<String> trustedCas;
        private String keyResolutionMethod = VPConstants.DEFAULT_KEY_RESOLUTION_METHOD;
        private String jwksUri;
        private String issuerPem;
        private List<ClaimConstraint> claims;

        public RequestedCredential() {

        }

        public String getCredentialId() {

            return credentialId;
        }

        public void setCredentialId(String credentialId) {

            this.credentialId = credentialId;
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

        public boolean isEnforceTrustedIssuer() {

            return enforceTrustedIssuer;
        }

        public void setEnforceTrustedIssuer(boolean enforceTrustedIssuer) {

            this.enforceTrustedIssuer = enforceTrustedIssuer;
        }

        public List<String> getTrustedCas() {

            return trustedCas != null ? new ArrayList<>(trustedCas) : new ArrayList<>();
        }

        public void setTrustedCas(List<String> trustedCas) {

            this.trustedCas = trustedCas != null ? new ArrayList<>(trustedCas) : null;
        }

        public String getKeyResolutionMethod() {

            return keyResolutionMethod;
        }

        public void setKeyResolutionMethod(String keyResolutionMethod) {

            this.keyResolutionMethod = keyResolutionMethod;
        }

        public String getJwksUri() {

            return jwksUri;
        }

        public void setJwksUri(String jwksUri) {

            this.jwksUri = jwksUri;
        }

        public String getIssuerPem() {

            return issuerPem;
        }

        public void setIssuerPem(String issuerPem) {

            this.issuerPem = issuerPem;
        }

        public List<ClaimConstraint> getClaims() {

            return claims != null ? new ArrayList<>(claims) : null;
        }

        public void setClaims(List<ClaimConstraint> claims) {

            this.claims = claims != null ? new ArrayList<>(claims) : null;
        }

    }

    /**
     * Represents a single claim constraint within a requested credential.
     *
     * <p>{@code id} and {@code path} map directly to the DCQL spec fields.
     * {@code mandatory} and {@code allowedValues} are WSO2 server-side enforcement
     * extensions; {@code allowedValues} is also serialised as the spec {@code values}
     * field in the outgoing DCQL query so the wallet can pre-filter.</p>
     */
    public static class ClaimConstraint implements Serializable {

        private static final long serialVersionUID = 1L;

        /** DCQL claim id — used to reference this claim in claim_sets. */
        private String id;
        /** DCQL path array, e.g. ["address", "street_address"]. */
        private List<String> path;
        private boolean mandatory = true;
        /** Maps to the DCQL 'values' field sent to the wallet and enforced server-side. */
        private List<String> allowedValues;

        public ClaimConstraint() {

        }

        public String getId() {

            return id;
        }

        public void setId(String id) {

            this.id = id;
        }

        public List<String> getPath() {

            return path != null ? new ArrayList<>(path) : null;
        }

        public void setPath(List<String> path) {

            this.path = path != null ? new ArrayList<>(path) : null;
        }

        public boolean isMandatory() {

            return mandatory;
        }

        public void setMandatory(boolean mandatory) {

            this.mandatory = mandatory;
        }

        public List<String> getAllowedValues() {

            return allowedValues != null ? new ArrayList<>(allowedValues) : null;
        }

        public void setAllowedValues(List<String> allowedValues) {

            this.allowedValues = allowedValues != null ? new ArrayList<>(allowedValues) : null;
        }
    }

    @Override
    public String toString() {

        return "PresentationDefinition{" +
                "definitionId='" + definitionId + '\'' +
                ", name='" + name + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }
}
