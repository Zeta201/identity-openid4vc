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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Resolves the issuer's public key from the {@code x5c} certificate chain embedded in the
 * SD-JWT VC JOSE header, as required by HAIP §6.1.1.
 *
 * <p>Validation steps:
 * <ol>
 *   <li>Extracts and decodes the {@code x5c} header from the issuer-signed JWT.</li>
 *   <li>Rejects self-signed leaf certificates (HAIP §6.1.1 MUST NOT).</li>
 *   <li>When {@code enforceTrustedIssuer} is enabled, validates the chain against the
 *       configured trusted CA PEMs using AKI/SKI matching.</li>
 *   <li>Converts the leaf certificate's public key to JWKS JSON for signature verification.</li>
 * </ol>
 */
public class X5cSignatureValidator implements CredentialSignatureValidator {

    private static final Log LOG = LogFactory.getLog(X5cSignatureValidator.class);

    @Override
    public String getValidatorType() {

        return TYPE_X5C;
    }

    @Override
    public void validateSignature(String issuerJwt, RequestedCredential requestedCredential)
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

        if (requestedCredential.isEnforceTrustedIssuer()) {
            validateAgainstTrustedCas(certificateChain, requestedCredential);
        } else {
            for (X509Certificate cert : certificateChain) {
                try {
                    cert.checkValidity();
                } catch (java.security.cert.CertificateExpiredException e) {
                    throw new VerificationClientException(VerificationErrorCode.EXPIRED_CREDENTIAL,
                            "A certificate in the x5c chain has expired: " + e.getMessage(), e);
                } catch (java.security.cert.CertificateNotYetValidException e) {
                    throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                            "A certificate in the x5c chain is not yet valid: " + e.getMessage(), e);
                }
            }
        }

        SignatureVerifier.verifyCredentialSignature(issuerJwt, leafCertToJwksJson(leafCertificate));
    }

    private void validateAgainstTrustedCas(List<X509Certificate> certificateChain,
                                            RequestedCredential requestedCredential)
            throws VerificationException {

        List<String> trustedCaPems = requestedCredential.getTrustedCas();
        if (trustedCaPems == null || trustedCaPems.isEmpty()) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "enforceTrustedIssuer is enabled but no trusted CA PEMs are configured.");
        }

        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to obtain CertificateFactory: " + e.getMessage(), e);
        }

        // Match the deepest cert's AKI against configured trusted CA SKIs.
        X509Certificate deepestCertInChain = certificateChain.getLast();
        byte[] deepestCertAuthorityKeyId = SignatureVerifier.extractAkiKeyIdentifier(deepestCertInChain);
        if (deepestCertAuthorityKeyId == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c chain validation failed: the deepest certificate has no AuthorityKeyIdentifier.");
        }

        X509Certificate matchedTrustedCa = null;
        for (String trustedCaPem : trustedCaPems) {
            if (StringUtils.isBlank(trustedCaPem)) {
                continue;
            }
            try {
                X509Certificate caCert = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(trustedCaPem.getBytes(StandardCharsets.UTF_8)));
                byte[] caSubjectKeyId = SignatureVerifier.extractSkiBytes(caCert);
                if (caSubjectKeyId != null && Arrays.equals(deepestCertAuthorityKeyId, caSubjectKeyId)) {
                    matchedTrustedCa = caCert;
                    break;
                }
            } catch (Exception e) {
                LOG.warn("Failed to parse configured trusted CA PEM; skipping: " + e.getMessage());
            }
        }
        if (matchedTrustedCa == null) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c chain did not match any configured trusted CA.");
        }
        SignatureVerifier.validateX5cChain(new ArrayList<>(certificateChain), matchedTrustedCa);
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
