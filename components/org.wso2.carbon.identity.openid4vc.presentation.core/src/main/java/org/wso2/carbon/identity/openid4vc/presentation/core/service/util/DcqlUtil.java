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

package org.wso2.carbon.identity.openid4vc.presentation.core.service.util;

import com.nimbusds.jose.jwk.ECKey;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.PresentationCoreConstants;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.KeyResolutionMethod;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationClaim;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.openid4vc.presentation.common.constant.Constants.VC_SD_JWT_FORMAT;

/**
 * Builds the DCQL (Digital Credentials Query Language) query for an OpenID4VP authorization request.
 */
public class DcqlUtil {

    private DcqlUtil() {

    }

    public static Map<String, Object> buildDcqlQuery(PresentationDefinition definition) {

        List<Map<String, Object>> credentials = new ArrayList<>();

        if (definition != null && definition.getCredentials() != null) {
            for (Credential credential : definition.getCredentials()) {
                if (credential == null) {
                    continue;
                }
                credentials.add(buildCredentialEntry(credential, credential.getIssuers()));
            }
        }

        Map<String, Object> dcqlQuery = new HashMap<>();
        dcqlQuery.put(Constants.DCQL.CREDENTIALS, credentials);

        if (!credentials.isEmpty()) {
            List<String> allCredentialIds = new ArrayList<>();
            for (Map<String, Object> cred : credentials) {
                allCredentialIds.add((String) cred.get(Constants.DCQL.ID));
            }
            Map<String, Object> credentialSet = new HashMap<>();
            credentialSet.put(Constants.DCQL.OPTIONS, Collections.singletonList(allCredentialIds));
            dcqlQuery.put(Constants.DCQL.CREDENTIAL_SETS, Collections.singletonList(credentialSet));
        }

        return dcqlQuery;
    }

    private static Map<String, Object> buildCredentialEntry(Credential credential, List<Issuer> issuers) {

        Map<String, Object> dcqlCredential = new HashMap<>();
        dcqlCredential.put(Constants.DCQL.ID, credential.getIdentifier());
        dcqlCredential.put(Constants.DCQL.FORMAT, credential.getFormat());

        if (!StringUtils.isBlank(credential.getType())) {
            Map<String, Object> meta = new HashMap<>();
            meta.put(Constants.DCQL.VCT_VALUES, Collections.singletonList(credential.getType()));
            dcqlCredential.put(Constants.DCQL.META, meta);
        }

        List<Map<String, Object>> claimsList = new ArrayList<>();
        List<String> mandatoryClaimIds = new ArrayList<>();
        boolean hasOptionalClaims = false;

        if (credential.getClaims() != null) {
            for (PresentationClaim claim : credential.getClaims()) {
                if (claim == null || StringUtils.isBlank(claim.getPath())) {
                    continue;
                }
                String claimId = claim.getPath();

                Map<String, Object> claimEntry = new HashMap<>();
                claimEntry.put(Constants.DCQL.ID, claimId);
                claimEntry.put(Constants.DCQL.PATH, Collections.singletonList(claim.getPath()));
                claimsList.add(claimEntry);

                if (claim.isMandatory()) {
                    mandatoryClaimIds.add(claimId);
                } else {
                    hasOptionalClaims = true;
                }
            }
        }
        if (!claimsList.isEmpty()) {
            dcqlCredential.put(Constants.DCQL.CLAIMS, claimsList);
        }
        if (hasOptionalClaims && !mandatoryClaimIds.isEmpty()) {
            List<String> allClaimIds = new ArrayList<>();
            for (Map<String, Object> claimEntry : claimsList) {
                allClaimIds.add((String) claimEntry.get(Constants.DCQL.ID));
            }
            dcqlCredential.put(Constants.DCQL.CLAIM_SETS, Arrays.asList(allClaimIds, mandatoryClaimIds));
        }

        addTrustedAuthorities(issuers, dcqlCredential);

        return dcqlCredential;
    }

    private static void addTrustedAuthorities(List<Issuer> issuers, Map<String, Object> dcqlCredential) {

        if (issuers == null || issuers.isEmpty()) {
            return;
        }
        List<String> akiValues = new ArrayList<>();
        for (Issuer issuer : issuers) {
            if (issuer.getKeyResolutionMethod() != KeyResolutionMethod.X5C) {
                continue;
            }
            String ski = extractSubjectKeyIdentifierHex(issuer.getCertificate());
            if (ski != null) {
                akiValues.add(ski);
            }
        }
        if (!akiValues.isEmpty()) {
            Map<String, Object> trustedAuthority = new HashMap<>();
            trustedAuthority.put(Constants.DCQL.TRUSTED_AUTHORITY_TYPE, Constants.DCQL.TRUSTED_AUTHORITY_TYPE_AKI);
            trustedAuthority.put(Constants.DCQL.TRUSTED_AUTHORITY_VALUES, akiValues);
            dcqlCredential.put(Constants.DCQL.TRUSTED_AUTHORITIES, Collections.singletonList(trustedAuthority));
        }
    }

    public static Map<String, Object> buildClientMetadata(String clientId, ECKey ephemeralPublicKey) {

        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put(PresentationCoreConstants.METADATA_CLIENT_NAME, clientId);

        Map<String, Object> vcSdJwt = new HashMap<>();
        vcSdJwt.put(PresentationCoreConstants.METADATA_SD_JWT_ALG_VALUES,
                Arrays.asList(Constants.Algorithms.ES256, Constants.Algorithms.EDDSA,
                        Constants.Algorithms.RS256));
        vcSdJwt.put(PresentationCoreConstants.METADATA_KB_JWT_ALG_VALUES,
                Arrays.asList(Constants.Algorithms.ES256, Constants.Algorithms.EDDSA));
        Map<String, Object> vpFormats = new HashMap<>();
        vpFormats.put(VC_SD_JWT_FORMAT, vcSdJwt);
        clientMetadata.put(PresentationCoreConstants.METADATA_VP_FORMATS, vpFormats);

        if (ephemeralPublicKey != null) {
            List<Object> keysList = new ArrayList<>();
            keysList.add(ephemeralPublicKey.toJSONObject());
            Map<String, Object> jwks = new HashMap<>();
            jwks.put(Constants.ClientMetadata.KEYS, keysList);
            clientMetadata.put(Constants.ClientMetadata.JWKS, jwks);
            clientMetadata.put(Constants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ALG,
                    Constants.Algorithms.ECDH_ES);
            clientMetadata.put(Constants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ENC,
                    Constants.Algorithms.A256GCM);
        }

        return clientMetadata;
    }

    /**
     * Parses a PEM-encoded X.509 certificate and returns its Subject Key Identifier (SKI)
     * as a lowercase hex string. The SKI of a CA cert matches the AKI extension of its issued leaf certs,
     * making it the correct value for DCQL {@code trusted_authorities} of type {@code aki}.
     *
     * Returns {@code null} if the certificate cannot be parsed or has no SKI extension.
     */
    private static String extractSubjectKeyIdentifierHex(String pemCertificate) {

        if (StringUtils.isBlank(pemCertificate)) {
            return null;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance(PresentationCoreConstants.JCA_X509);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pemCertificate.getBytes(StandardCharsets.UTF_8)));
            SubjectKeyIdentifier ski = SubjectKeyIdentifier.fromExtensions(
                    new JcaX509CertificateHolder(cert).getExtensions());
            return ski != null ? HexFormat.of().formatHex(ski.getKeyIdentifier()) : null;
        } catch (Exception e) {
            return null;
        }
    }
}
