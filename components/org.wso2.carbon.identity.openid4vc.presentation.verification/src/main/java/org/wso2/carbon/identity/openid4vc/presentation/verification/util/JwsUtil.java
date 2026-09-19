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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

import java.security.PublicKey;
import java.util.Set;

/**
 * Low-level JWS verification utility: algorithm allowlist enforcement and signature verification.
 */
public class JwsUtil {

    public static final Set<String> ALLOWED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256.getName(),
            JWSAlgorithm.RS384.getName(),
            JWSAlgorithm.RS512.getName(),
            JWSAlgorithm.PS256.getName(),
            JWSAlgorithm.PS384.getName(),
            JWSAlgorithm.PS512.getName(),
            JWSAlgorithm.ES256.getName(),
            JWSAlgorithm.ES384.getName(),
            JWSAlgorithm.ES512.getName(),
            JWSAlgorithm.EdDSA.getName()
    );

    private JwsUtil() {

    }

    /**
     * Verifies a JWT signature using a provided public key and JWS algorithm.
     * Rejects disallowed algorithms and detects algorithm-switching attacks before
     * attempting cryptographic verification.
     *
     * @param signedJwt the parsed JWT to verify
     * @param publicKey the public key to verify against
     * @param algorithm the expected JWS algorithm identifier
     * @return {@code true} if the signature is valid; otherwise {@code false}
     * @throws VerificationException if the algorithm is disallowed or verification fails
     */
    public static boolean verifySignatureWithPublicKey(SignedJWT signedJwt, PublicKey publicKey, String algorithm)
            throws VerificationException {

        if (algorithm == null || JWSAlgorithm.NONE.getName().equalsIgnoreCase(algorithm)
                || !ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw VerificationExceptionHandler.handleClientException(
                    VerificationErrorCode.UNSUPPORTED_SIGNING_ALGORITHM);
        }
        try {
            // Prevent algorithm-switching: the JWT header must agree with the pre-validated algorithm.
            if (!algorithm.equals(signedJwt.getHeader().getAlgorithm().getName())) {
                throw VerificationExceptionHandler.handleClientException(
                        VerificationErrorCode.UNSUPPORTED_SIGNING_ALGORITHM);
            }
            JWSVerifier jwsVerifier = new DefaultJWSVerifierFactory().createJWSVerifier(
                    signedJwt.getHeader(), publicKey);
            return signedJwt.verify(jwsVerifier);
        } catch (JOSEException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_SIGNATURE);
        }
    }
}
