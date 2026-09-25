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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing a Presentation Definition.
 * This defines the credential requirements for a Verifiable Presentation request.
 * Use {@link Builder} to construct instances.
 */
public class PresentationDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private Integer cursorKey;
    private String identifier;
    private String displayName;
    private String description;
    private int tenantId;
    private List<Credential> credentials;

    private PresentationDefinition(Builder builder) {

        this.id = builder.id;
        this.cursorKey = builder.cursorKey;
        this.identifier = builder.identifier;
        this.displayName = builder.displayName;
        this.description = builder.description;
        this.tenantId = builder.tenantId;
        this.credentials = builder.credentials;
    }

    public String getId() {

        return id;
    }

    public Integer getCursorKey() {

        return cursorKey;
    }

    public String getIdentifier() {

        return identifier;
    }

    public String getDisplayName() {

        return displayName;
    }

    public String getDescription() {

        return description;
    }

    public int getTenantId() {

        return tenantId;
    }

    public List<Credential> getCredentials() {

        return credentials != null ? new ArrayList<>(credentials) : null;
    }

    /**
     * Builder for {@link PresentationDefinition}.
     */
    public static class Builder {

        private String id;
        private Integer cursorKey;
        private String identifier;
        private String displayName;
        private String description;
        private int tenantId;
        private List<Credential> credentials;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder cursorKey(Integer cursorKey) {

            this.cursorKey = cursorKey;
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

        public Builder credentials(List<Credential> credentials) {

            this.credentials = credentials != null ? new ArrayList<>(credentials) : null;
            return this;
        }

        public PresentationDefinition build() {

            return new PresentationDefinition(this);
        }
    }

    @Override
    public String toString() {

        return "PresentationDefinition{" +
                "id='" + id + '\'' +
                ", identifier='" + identifier + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }
}
