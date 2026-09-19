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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.CredentialSignatureValidator;
import org.wso2.carbon.identity.openid4vc.presentation.verification.signature.SignatureValidationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.HttpClientUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.JwsUtil;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationExceptionHandler;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;

import java.text.ParseException;

/**
 * Resolves the issuer's public key from a JWKS endpoint URI configured on the {@link Issuer}.
 */
public class JwksValidator implements CredentialSignatureValidator {

    @Override
    public String getValidatorType() {

        return TYPE_JWKS_URI;
    }

    @Override
    public void validateSignature(SignatureValidationContext context)
            throws VerificationException {

        SignedJWT issuerJwt = context.getIssuerJwt();
        Issuer issuer = context.getIssuer();
        String jwksUri = issuer.getJwksUri();
        if (StringUtils.isBlank(jwksUri)) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.ISSUER_NOT_FOUND,
                    new IllegalStateException("JWKS URI is not configured for issuer."));
        }
        String jwksJson;
        try {
            jwksJson = HttpClientUtil.fetchContent(jwksUri);
            if (StringUtils.isBlank(jwksJson)) {
                throw VerificationExceptionHandler.handleServerException(
                        VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        new IllegalStateException("JWKS endpoint returned an empty response."));
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.JWKS_RESOLUTION_ERROR, e);
        }
        verifyAgainstJwks(issuerJwt, jwksJson);
    }

    private static void verifyAgainstJwks(SignedJWT issuerJwt, String jwksJson)
            throws VerificationException {

        String signingAlgorithm = issuerJwt.getHeader().getAlgorithm().getName();
        if (signingAlgorithm == null || JWSAlgorithm.NONE.getName().equalsIgnoreCase(signingAlgorithm)
                || !JwsUtil.ALLOWED_ALGORITHMS.contains(signingAlgorithm)) {
            throw VerificationExceptionHandler.handleClientException(
                    VerificationErrorCode.UNSUPPORTED_SIGNING_ALGORITHM);
        }

        try {
            JWKSet jwkSet = JWKSet.parse(jwksJson);
            JWKSource<SecurityContext> jwkKeySource = new ImmutableJWKSet<>(jwkSet);

            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier<>(
                            new JOSEObjectType("jwt"),
                            JOSEObjectType.JWT,
                            new JOSEObjectType(Constants.VC_SD_JWT_FORMAT)
                    )
            );
            jwtProcessor.setJWSKeySelector(
                    new JWSVerificationKeySelector<>(JWSAlgorithm.parse(signingAlgorithm), jwkKeySource));
            jwtProcessor.process(issuerJwt, null);

        } catch (ParseException e) {
            throw VerificationExceptionHandler.handleServerException(
                    VerificationErrorCode.JWKS_RESOLUTION_ERROR, e);
        } catch (BadJOSEException | JOSEException e) {
            throw VerificationExceptionHandler.handleClientException(VerificationErrorCode.INVALID_SIGNATURE);
        }
    }
}
