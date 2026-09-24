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

/**
 * Represents a trusted issuer configuration for a single credential within a Presentation Definition.
 *
 * <p>Each instance specifies how to resolve the issuer's public key at verification time:
 * <ul>
 *   <li>{@link KeyResolutionMethod#JWKS_URI} — {@link #jwksUri} holds the endpoint to fetch the JWKS from.</li>
 *   <li>{@link KeyResolutionMethod#PEM} — {@link #certificate} holds a PEM-encoded X.509 certificate.</li>
 *   <li>{@link KeyResolutionMethod#X5C} — {@link #certificate} holds a trusted CA PEM certificate;
 *       the signing key is taken from the {@code x5c} chain in the JWT header.</li>
 * </ul>
 */
public class Issuer implements Serializable {

    private static final long serialVersionUID = 1L;

    private KeyResolutionMethod keyResolutionMethod;
    private String issuerUrl;
    private String jwksUri;
    private String certificate;

    public Issuer() {

    }

    /**
     * Supported methods for resolving an issuer's public key during credential verification.
     */
    public enum KeyResolutionMethod {

        JWKS_URI,   // Public key fetched at runtime from a JWKS endpoint URI.
        PEM,        // Public key derived from a PEM-encoded X.509 certificate.
        X5C         // Root CA certificate trust anchored to an issuer.
    }

    public KeyResolutionMethod getKeyResolutionMethod() {

        return keyResolutionMethod;
    }

    public void setKeyResolutionMethod(KeyResolutionMethod keyResolutionMethod) {

        this.keyResolutionMethod = keyResolutionMethod;
    }

    public String getIssuerUrl() {

        return issuerUrl;
    }

    public void setIssuerUrl(String issuerUrl) {

        this.issuerUrl = issuerUrl;
    }

    public String getJwksUri() {

        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {

        this.jwksUri = jwksUri;
    }

    public String getCertificate() {

        return certificate;
    }

    public void setCertificate(String certificate) {

        this.certificate = certificate;
    }
}
