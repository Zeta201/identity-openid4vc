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

package org.wso2.carbon.identity.openid4vc.presentation.verification.signature.impl;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.verification.constant.VerificationConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.SignatureValidationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.JwsUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationExceptionHandler;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Resolves the issuer's public key from the {@code x5c} certificate chain embedded in the
 * SD-JWT VC JOSE header, as required by HAIP §6.1.1.
 *
 * <p>Validation steps:
 * <ol>
 *   <li>Extracts and decodes the {@code x5c} header from the issuer-signed JWT.</li>
 *   <li>Rejects self-signed leaf certificates (HAIP §6.1.1 MUST NOT).</li>
 *   <li>Validates the chain against the trusted CA cert in the {@link Issuer} using AKI/SKI matching.</li>
 *   <li>Verifies the JWT signature using the leaf certificate's public key.</li>
 * </ol>
 */
public class X5cValidator implements CredentialSignatureValidator {

    @Override
    public String getValidatorType() {

        return TYPE_X5C;
    }

    @Override
    public void validateSignature(SignatureValidationContext context)
            throws VerificationException {

        SignedJWT issuerJwt = context.getIssuerJwt();
        Issuer issuer = context.getIssuer();
        List<Base64> x5cHeader = issuerJwt.getHeader().getX509CertChain();
        if (x5cHeader == null || x5cHeader.isEmpty()) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_X5C_CHAIN);
        }

        List<X509Certificate> certificateChain = decodeCertChain(x5cHeader);
        X509Certificate leafCertificate = certificateChain.getFirst();

        // HAIP §6.1.1: the signing certificate MUST NOT be self-signed.
        if (leafCertificate.getSubjectX500Principal().equals(leafCertificate.getIssuerX500Principal())) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_X5C_CHAIN);
        }

        validateAgainstTrustedCa(certificateChain, issuer);

        String algorithm = issuerJwt.getHeader().getAlgorithm().getName();
        if (!JwsUtil.verifySignatureWithPublicKey(issuerJwt, leafCertificate.getPublicKey(), algorithm)) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_SIGNATURE);
        }
    }

    private void validateAgainstTrustedCa(List<X509Certificate> certificateChain,
            Issuer issuer) throws VerificationException {

        String trustedCaCertificate = issuer.getCertificate();
        if (StringUtils.isBlank(trustedCaCertificate)) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.TRUST_ANCHOR_NOT_CONFIGURED,
                    new IllegalStateException("Trusted CA certificate is not configured for issuer."));
        }

        X509Certificate caCert;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
            caCert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(trustedCaCertificate.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.INTERNAL_SERVER_ERROR, e);
        }

        validateChain(certificateChain, caCert);
    }

    private static List<X509Certificate> decodeCertChain(List<Base64> x5cChain)
            throws VerificationClientException {

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
            List<X509Certificate> certChain = new ArrayList<>();
            for (Base64 encodedCert : x5cChain) {
                certChain.add((X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(encodedCert.decode())));
            }
            return certChain;
        } catch (CertificateException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_X5C_CHAIN);
        }
    }

    private static void validateChain(List<X509Certificate> certificateChain, X509Certificate trustAnchorCert)
            throws VerificationException {

        if (certificateChain == null || certificateChain.isEmpty()) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_X5C_CHAIN);
        }
        if (trustAnchorCert == null) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.TRUST_ANCHOR_NOT_CONFIGURED,
                    new IllegalStateException("Trust anchor certificate resolved to null."));
        }

        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
        } catch (CertificateException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.INTERNAL_SERVER_ERROR, e);
        }

        try {
            for (X509Certificate cert : certificateChain) {
                cert.checkValidity();
            }
            CertPath certPath = certFactory.generateCertPath(certificateChain);
            PKIXParameters pkixParams = new PKIXParameters(
                    Collections.singleton(new TrustAnchor(trustAnchorCert, null)));
            pkixParams.setRevocationEnabled(false);
            CertPathValidator.getInstance(VerificationConstants.JCA_PKIX).validate(certPath, pkixParams);
        } catch (CertificateExpiredException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.EXPIRED_CREDENTIAL);
        } catch (CertificateNotYetValidException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.CERTIFICATE_NOT_YET_VALID);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.INTERNAL_SERVER_ERROR, e);
        } catch (Exception e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_X5C_CHAIN);
        }
    }
}
