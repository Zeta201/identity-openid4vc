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

package org.wso2.carbon.identity.openid4vc.presentation.verification.constant;

/**
 * Constants and general constraints for the OpenID4VP presentation verification component.
 */
public class VerificationConstants {

    private VerificationConstants() {

    }

    /**
     * JCA/JCE provider algorithm name constants.
     */
    public static final String JCA_X509 = "X.509";
    public static final String JCA_PKIX = "PKIX";

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
     * JWK key type ({@code kty}) string constants.
     */
    public static final String JWK_KEY_TYPE_EC = "EC";
    public static final String JWK_KEY_TYPE_RSA = "RSA";
    public static final String JWK_KEY_TYPE_OKP = "OKP";

}
