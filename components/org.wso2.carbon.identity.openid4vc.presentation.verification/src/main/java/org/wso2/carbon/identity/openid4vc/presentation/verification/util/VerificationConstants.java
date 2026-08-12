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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;


/**
 * Constants and general constraints for the OpenID4VC verification component.
 */
public class VerificationConstants {

    /**
     * Creates a constants holder instance.
     *
     * <p>This constructor is intentionally private because this class exposes
     * only {@code public static final} constants.</p>
     */
    private VerificationConstants() {

    }

    /**
     * Protocol prefixes.
     */
    public static final String HTTP_PREFIX = "http";
    public static final String HTTPS_PREFIX = "https";
    public static final String HTTPS_SCHEME = "https://";

    /**
     * URI fragment separator.
     */
    public static final String FRAGMENT_PREFIX = "#";


    /**
     * JCA/JCE provider algorithm name constants.
     */
    public static final String JCA_X509 = "X.509";
    public static final String JCA_PKIX = "PKIX";
    public static final String JCA_PKCS12 = "PKCS12";

    /**
     * JCA digest algorithm names.
     */
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_384 = "SHA-384";
    public static final String SHA_512 = "SHA-512";

    /**
     * SD-JWT {@code _sd_alg} hash algorithm identifiers (lowercase, per IANA registry).
     */
    public static final String SD_JWT_HASH_ALG_SHA_256 = "sha-256";
    public static final String SD_JWT_HASH_ALG_SHA_384 = "sha-384";
    public static final String SD_JWT_HASH_ALG_SHA_512 = "sha-512";

    /**
     * HTTP header names.
     */
    public static final String HTTP_HEADER_ACCEPT = "Accept";

    /**
     * WSO2 ServerConfiguration property keys for the IS trust store.
     */
    public static final String CONFIG_TRUSTSTORE_LOCATION = "Security.TrustStore.Location";
    public static final String CONFIG_TRUSTSTORE_PASSWORD = "Security.TrustStore.Password";
    public static final String CONFIG_TRUSTSTORE_TYPE = "Security.TrustStore.Type";

    /**
     * Holder-binding method identifier for {@code cnf.jwk} key binding in SD-JWT.
     */
    public static final String HOLDER_BINDING_CNF_JWK = "cnf.jwk";

    /**
     * Verification status messages.
     */
    public static final String STATUS_VERIFICATION_SUCCESS = "Verification successful";
    public static final String STATUS_VERIFICATION_FAILED = "Verification failed";

    /**
     * Error message templates and constraints.
     */
    public static final String ERROR_INVALID_VP_TOKEN = "VP token is missing or empty.";

    /**
     * JOSE type string for plain JWT ({@code typ: "jwt"}, lowercase).
     * Distinct from {@link com.nimbusds.jose.JOSEObjectType#JWT} which uses uppercase {@code "JWT"}.
     */
    public static final String JOSE_TYPE_JWT = "jwt";

    /**
     * JWK key type ({@code kty}) string constants.
     */
    public static final String JWK_KEY_TYPE_EC = "EC";
    public static final String JWK_KEY_TYPE_RSA = "RSA";
    public static final String JWK_KEY_TYPE_OKP = "OKP";

    /**
     * JCA/JCE EC curve name constants used for multicodec key decoding.
     */
    public static final String EC_CURVE_SECP256R1 = "secp256r1";
    public static final String EC_CURVE_SECP384R1 = "secp384r1";

    /**
     * Raw public key byte lengths for EdDSA curves, as fixed by RFC 8410.
     * Used to extract the key material from the SubjectPublicKeyInfo DER encoding.
     */
    public static final int ED25519_PUBLIC_KEY_BYTE_LENGTH = 32;
    public static final int ED448_PUBLIC_KEY_BYTE_LENGTH = 57;

    public static final String SD_JWT_DELIMITER = "~";
}
