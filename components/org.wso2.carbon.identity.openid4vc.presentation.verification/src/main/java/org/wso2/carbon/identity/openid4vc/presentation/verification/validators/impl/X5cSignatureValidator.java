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

package org.wso2.carbon.identity.openid4vc.presentation.verification.validators.impl;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.SignatureVerifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.validators.CredentialSignatureValidator;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Resolves the issuer's public key from the {@code x5c} certificate chain embedded in the
 * SD-JWT VC JOSE header, as required by HAIP §6.1.1.
 *
 * <p>Validation steps:
 * <ol>
 *   <li>Extracts and decodes the {@code x5c} header from the issuer-signed JWT.</li>
 *   <li>Rejects self-signed leaf certificates (HAIP §6.1.1 MUST NOT).</li>
 *   <li>Validates the chain against the trusted CA cert in the issuer config using AKI/SKI matching.</li>
 *   <li>Converts the leaf certificate's public key to JWKS JSON for signature verification.</li>
 * </ol>
 */
public class X5cSignatureValidator implements CredentialSignatureValidator {

    @Override
    public String getValidatorType() {

        return TYPE_X5C;
    }

    @Override
    public void validateSignature(String issuerJwt, DcqlQuery.IssuerConfig issuerConfig)
            throws VerificationException {

        List<Base64> x5cHeader;
        try {
            x5cHeader = SignedJWT.parse(issuerJwt).getHeader().getX509CertChain();
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to parse issuer JWT JOSE header: " + e.getMessage(), e);
        }
        if (x5cHeader == null || x5cHeader.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "SD-JWT VC is missing the required x5c header.");
        }

        List<X509Certificate> certificateChain = SignatureVerifier.decodeCertChain(x5cHeader);
        X509Certificate leafCertificate = certificateChain.getFirst();

        // HAIP §6.1.1: the signing certificate MUST NOT be self-signed.
        if (leafCertificate.getSubjectX500Principal().equals(leafCertificate.getIssuerX500Principal())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "The SD-JWT VC signing certificate is self-signed.");
        }

        validateAgainstTrustedCa(certificateChain, issuerConfig);

        SignatureVerifier.verifyCredentialSignature(issuerJwt, leafCertToJwksJson(leafCertificate));
    }

    private void validateAgainstTrustedCa(List<X509Certificate> certificateChain,
            DcqlQuery.IssuerConfig issuerConfig) throws VerificationException {

        String trustedCaPem = issuerConfig.getKeySource();
        if (StringUtils.isBlank(trustedCaPem)) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "x5c issuer config is missing the required trusted CA certificate.");
        }

        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to obtain CertificateFactory: " + e.getMessage(), e);
        }

        // Match the deepest cert's AKI against the configured trusted CA's SKI.
        X509Certificate deepestCertInChain = certificateChain.getLast();
        Optional<byte[]> deepestCertAuthorityKeyId = SignatureVerifier.extractAkiKeyIdentifier(deepestCertInChain);
        if (deepestCertAuthorityKeyId.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c chain validation failed: the deepest certificate has no AuthorityKeyIdentifier.");
        }

        X509Certificate caCert;
        try {
            caCert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(trustedCaPem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to parse configured trusted CA certificate: " + e.getMessage(), e);
        }

        Optional<byte[]> caSubjectKeyId = SignatureVerifier.extractSkiBytes(caCert);
        if (caSubjectKeyId.isEmpty() || !Arrays.equals(deepestCertAuthorityKeyId.get(), caSubjectKeyId.get())) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c chain did not match the configured trusted CA.");
        }
        SignatureVerifier.validateX5cChain(certificateChain, caCert);
    }

    private static String leafCertToJwksJson(X509Certificate leafCertificate) throws VerificationException {

        PublicKey leafPublicKey = leafCertificate.getPublicKey();
        try {
            JWK leafJwk;
            if (leafPublicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) leafPublicKey;
                Curve ecCurve = Curve.forECParameterSpec(ecPublicKey.getParams());
                if (ecCurve == null) {
                    throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                            "Unsupported EC curve in x5c leaf certificate.");
                }
                leafJwk = new ECKey.Builder(ecCurve, ecPublicKey).build();
            } else if (leafPublicKey instanceof RSAPublicKey) {
                leafJwk = new RSAKey.Builder((RSAPublicKey) leafPublicKey).build();
            } else if (leafPublicKey instanceof EdECPublicKey) {
                EdECPublicKey edPublicKey = (EdECPublicKey) leafPublicKey;
                byte[] encodedKeyBytes = edPublicKey.getEncoded();
                boolean isEd448 = VPConstants.Algorithms.ED448.equals(edPublicKey.getParams().getName());
                Curve edCurve = isEd448 ? Curve.Ed448 : Curve.Ed25519;
                int edKeyByteLength = isEd448 ? VerificationConstants.ED448_PUBLIC_KEY_BYTE_LENGTH
                        : VerificationConstants.ED25519_PUBLIC_KEY_BYTE_LENGTH;
                byte[] rawPublicKeyBytes = Arrays.copyOfRange(encodedKeyBytes,
                        encodedKeyBytes.length - edKeyByteLength, encodedKeyBytes.length);
                leafJwk = new OctetKeyPair.Builder(edCurve, Base64URL.encode(rawPublicKeyBytes)).build();
            } else {
                throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        "Unsupported public key type in x5c leaf certificate: " + leafPublicKey.getAlgorithm());
            }
            return new JWKSet(leafJwk.toPublicJWK()).toJSONObject(true).toString();
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Failed to convert x5c leaf certificate public key to JWKS: " + e.getMessage(), e);
        }
    }
}
