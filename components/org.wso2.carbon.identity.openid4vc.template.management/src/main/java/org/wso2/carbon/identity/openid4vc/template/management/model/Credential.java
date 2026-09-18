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
 * Represents a single requested credential within a Presentation Definition.
 */
public class Credential implements Serializable {

    private static final long serialVersionUID = 1L;

    private String identifier;
    private String format;
    private String type;
    private List<Issuer> issuers;
    private List<PresentationClaim> claims;

    public Credential() {

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

    public List<Issuer> getIssuers() {

        return issuers != null ? new ArrayList<>(issuers) : null;
    }

    public void setIssuers(List<Issuer> issuers) {

        this.issuers = issuers != null ? new ArrayList<>(issuers) : null;
    }

    public List<PresentationClaim> getClaims() {

        return claims != null ? new ArrayList<>(claims) : null;
    }

    public void setClaims(List<PresentationClaim> claims) {

        this.claims = claims != null ? new ArrayList<>(claims) : null;
    }
}
