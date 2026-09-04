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

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
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
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

/**
 * Resolves the issuer's public key from a PEM-encoded certificate configured on the issuer config.
 */
public class PemSignatureValidator implements CredentialSignatureValidator {

    @Override
    public String getValidatorType() {

        return TYPE_PEM;
    }

    @Override
    public void validateSignature(String issuerJwt, DcqlQuery.IssuerConfig issuerConfig)
            throws VerificationException {

        String certData = issuerConfig.getKeySource();
        if (StringUtils.isBlank(certData)) {
            throw new VerificationClientException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "PEM validator requires a non-blank issuer PEM certificate to be configured.");
        }
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
            X509Certificate issuerCert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certData.getBytes(StandardCharsets.UTF_8)));
            issuerCert.checkValidity();
            PublicKey issuerPublicKey = issuerCert.getPublicKey();
            String signingAlgorithm = SignedJWT.parse(issuerJwt).getHeader().getAlgorithm().getName();
            if (!SignatureVerifier.verifySignatureWithPublicKey(issuerJwt, issuerPublicKey, signingAlgorithm)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "Credential signature verification failed.");
            }
        } catch (VerificationException e) {
            throw e;
        } catch (CertificateExpiredException e) {
            throw new VerificationClientException(VerificationErrorCode.EXPIRED_CREDENTIAL,
                    "The configured issuer PEM certificate has expired: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "The configured issuer PEM certificate is not yet valid: " + e.getMessage(), e);
        } catch (ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse issuer JWT: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                    "Failed to parse issuer PEM certificate: " + e.getMessage(), e);
        }
    }
}
