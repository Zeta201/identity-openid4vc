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
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
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

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.VC_SD_JWT_FORMAT;

/**
 * Utility class for building DCQL (Digital Credentials Query Language) structures
 * used in OpenID4VP presentation requests.
 *
 * <p>Covers two responsibilities:
 * <ul>
 *   <li>Translating a {@link PresentationDefinition} into the {@code dcql_query} JSON object
 *       sent to the wallet in the authorization request.</li>
 *   <li>Building the {@code client_metadata} object that advertises supported VP formats,
 *       accepted algorithms, and — when encrypted responses are required — the ephemeral
 *       public key the wallet should use for ECDH-ES encryption.</li>
 * </ul>
 */
public class DcqlUtil {

    private DcqlUtil() {

    }

    /**
     * Builds the {@code dcql_query} object from a {@link PresentationDefinition}.
     *
     * <p>Each credential in the definition becomes one entry in the {@code credentials} array.
     * When there is at least one credential, a single {@code credential_sets} entry is appended
     * that requires all credentials to be satisfied together.
     *
     * @param definition the presentation definition to convert; may be {@code null}
     * @return the {@code dcql_query} map, with an empty {@code credentials} list if the definition
     *         is {@code null} or contains no credentials
     */
    public static Map<String, Object> buildDcqlQuery(PresentationDefinition definition) {

        // Collect DCQL credential entries from each non-null credential in the definition.
        List<Map<String, Object>> credentials = new ArrayList<>();

        if (definition != null && definition.getCredentials() != null) {
            for (Credential credential : definition.getCredentials()) {
                if (credential == null) {
                    continue;
                }
                // Build and collect the DCQL entry for this credential.
                credentials.add(buildCredentialEntry(credential, credential.getIssuers()));
            }
        }

        // Assemble the top-level dcql_query object.
        Map<String, Object> dcqlQuery = new HashMap<>();
        dcqlQuery.put(Constants.DCQL.CREDENTIALS, credentials);

        if (!credentials.isEmpty()) {
            // Collect all credential IDs to form a single credential set that requires all of them.
            List<String> allCredentialIds = new ArrayList<>();
            for (Map<String, Object> cred : credentials) {
                allCredentialIds.add((String) cred.get(Constants.DCQL.ID));
            }
            // Wrap the IDs into a credential_set with one option that must be fully satisfied.
            Map<String, Object> credentialSet = new HashMap<>();
            credentialSet.put(Constants.DCQL.OPTIONS, Collections.singletonList(allCredentialIds));
            dcqlQuery.put(Constants.DCQL.CREDENTIAL_SETS, Collections.singletonList(credentialSet));
        }

        return dcqlQuery;
    }

    /**
     * Builds a single DCQL credential entry for the given {@link Credential}.
     *
     * <p>Sets the {@code id}, {@code format}, and optionally {@code meta} (for type constraints),
     * {@code claims} (for selective disclosure), {@code claim_sets} (when both mandatory and
     * optional claims are present), and {@code trusted_authorities} (for issuer pinning).
     *
     * @param credential the credential definition to convert
     * @param issuers    the list of trusted issuers; used to populate {@code trusted_authorities}
     * @return the DCQL credential entry map
     */
    private static Map<String, Object> buildCredentialEntry(Credential credential, List<Issuer> issuers) {

        // Initialize the credential entry with its identifier and format.
        Map<String, Object> dcqlCredential = new HashMap<>();
        dcqlCredential.put(Constants.DCQL.ID, credential.getIdentifier());
        dcqlCredential.put(Constants.DCQL.FORMAT, credential.getFormat());

        if (!StringUtils.isBlank(credential.getType())) {
            // Constrain the accepted credential type via the meta.vct_values field.
            Map<String, Object> meta = new HashMap<>();
            meta.put(Constants.DCQL.VCT_VALUES, Collections.singletonList(credential.getType()));
            dcqlCredential.put(Constants.DCQL.META, meta);
        }

        // Accumulate claim entries, tracking which are mandatory for claim_sets construction.
        List<Map<String, Object>> claimsList = new ArrayList<>();
        List<String> mandatoryClaimIds = new ArrayList<>();
        boolean hasOptionalClaims = false;

        if (credential.getClaims() != null) {
            for (PresentationClaim claim : credential.getClaims()) {
                if (claim == null || StringUtils.isBlank(claim.getPath())) {
                    continue;
                }
                // Split the dotted path into segments for the DCQL path array.
                String[] pathSegments = claim.getPath().split("\\.");
                // Derive a stable claim ID by joining path segments with underscores.
                String claimId = String.join("_", pathSegments);

                // Build the claim entry with its id and path array.
                Map<String, Object> claimEntry = new HashMap<>();
                claimEntry.put(Constants.DCQL.ID, claimId);
                claimEntry.put(Constants.DCQL.PATH, Arrays.asList(pathSegments));
                claimsList.add(claimEntry);

                if (claim.isMandatory()) {
                    // Track mandatory claim IDs for use in the claim_sets fallback option.
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
            // Emit two claim_set options: all claims preferred, mandatory-only as fallback.
            List<String> allClaimIds = new ArrayList<>();
            for (Map<String, Object> claimEntry : claimsList) {
                allClaimIds.add((String) claimEntry.get(Constants.DCQL.ID));
            }
            dcqlCredential.put(Constants.DCQL.CLAIM_SETS, Arrays.asList(allClaimIds, mandatoryClaimIds));
        }

        // Append trusted_authorities if any X5C-based issuers are configured.
        addTrustedAuthorities(issuers, dcqlCredential);

        return dcqlCredential;
    }

    /**
     * Appends a {@code trusted_authorities} entry to the credential map when at least one
     * X5C-based issuer has a parseable certificate with a Subject Key Identifier extension.
     *
     * <p>Only issuers whose {@code keyResolutionMethod} is {@link KeyResolutionMethod#X5C} are
     * considered. The SKI hex of each qualifying issuer certificate is used as an AKI value,
     * which the wallet matches against the Authority Key Identifier of the presented credential.
     *
     * @param issuers       the issuers configured on the credential; may be {@code null} or empty
     * @param dcqlCredential the credential map to mutate in-place
     */
    private static void addTrustedAuthorities(List<Issuer> issuers, Map<String, Object> dcqlCredential) {

        if (issuers == null || issuers.isEmpty()) {
            return;
        }
        // Collect SKI hex values from X5C issuers whose certificate can be parsed.
        List<String> akiValues = new ArrayList<>();
        for (Issuer issuer : issuers) {
            // Skip issuers that don't use certificate-based key resolution.
            if (issuer.getKeyResolutionMethod() != KeyResolutionMethod.X5C) {
                continue;
            }
            // Extract the SKI from the issuer certificate; skip if absent or unparseable.
            String ski = extractSubjectKeyIdentifierHex(issuer.getCertificate());
            if (ski != null) {
                akiValues.add(ski);
            }
        }
        if (!akiValues.isEmpty()) {
            // Build a single trusted_authority entry of type "aki" with all collected values.
            Map<String, Object> trustedAuthority = new HashMap<>();
            trustedAuthority.put(Constants.DCQL.TRUSTED_AUTHORITY_TYPE, Constants.DCQL.TRUSTED_AUTHORITY_TYPE_AKI);
            trustedAuthority.put(Constants.DCQL.TRUSTED_AUTHORITY_VALUES, akiValues);
            dcqlCredential.put(Constants.DCQL.TRUSTED_AUTHORITIES, Collections.singletonList(trustedAuthority));
        }
    }

    /**
     * Builds the {@code client_metadata} object included in the presentation request.
     *
     * <p>Always advertises the supported VP formats and accepted signing/key-binding algorithms.
     * When {@code ephemeralPublicKey} is non-null, also includes the JWKS and encryption parameters
     * ({@code ECDH-ES} + {@code A256GCM}) that instruct the wallet to encrypt its response.
     *
     * @param clientId          the {@code client_id} of this server, used as the display name
     * @param ephemeralPublicKey the ephemeral EC public key for encrypted responses;
     *                          {@code null} when encryption is not required
     * @return the client metadata map ready to be serialized into the authorization request
     */
    public static Map<String, Object> buildClientMetadata(String clientId, ECKey ephemeralPublicKey) {

        // Initialize metadata with the client display name.
        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put(PresentationCoreConstants.METADATA_CLIENT_NAME, clientId);

        // Declare supported SD-JWT VC algorithms for credential signature and key-binding.
        Map<String, Object> vcSdJwt = new HashMap<>();
        vcSdJwt.put(PresentationCoreConstants.METADATA_SD_JWT_ALG_VALUES,
                Arrays.asList(Constants.Algorithms.ES256, Constants.Algorithms.EDDSA,
                        Constants.Algorithms.RS256));
        vcSdJwt.put(PresentationCoreConstants.METADATA_KB_JWT_ALG_VALUES,
                Arrays.asList(Constants.Algorithms.ES256, Constants.Algorithms.EDDSA));
        // Wrap the format-specific algorithms into the vp_formats map.
        Map<String, Object> vpFormats = new HashMap<>();
        vpFormats.put(VC_SD_JWT_FORMAT, vcSdJwt);
        clientMetadata.put(PresentationCoreConstants.METADATA_VP_FORMATS, vpFormats);

        if (ephemeralPublicKey != null) {
            // Include the ephemeral public key so the wallet can encrypt its response.
            List<Object> keysList = new ArrayList<>();
            keysList.add(ephemeralPublicKey.toJSONObject());
            Map<String, Object> jwks = new HashMap<>();
            jwks.put(Constants.ClientMetadata.KEYS, keysList);
            clientMetadata.put(Constants.ClientMetadata.JWKS, jwks);
            // Specify ECDH-ES as the key agreement algorithm and A256GCM as the content encryption.
            clientMetadata.put(Constants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ALG,
                    Constants.Algorithms.ECDH_ES);
            clientMetadata.put(Constants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ENC,
                    Constants.Algorithms.A256GCM);
        }

        return clientMetadata;
    }

    /**
     * Parses a PEM-encoded X.509 certificate and returns its Subject Key Identifier (SKI)
     * as a lowercase hex string.
     *
     * <p>The SKI of a CA certificate matches the Authority Key Identifier (AKI) of leaf
     * certificates it issued, making it the correct value for DCQL {@code trusted_authorities}
     * entries of type {@code aki}.
     *
     * @param pemCertificate PEM-encoded X.509 certificate string; may be blank
     * @return the SKI as a lowercase hex string, or {@code null} if the certificate is blank,
     *         cannot be parsed, or has no SKI extension
     */
    private static String extractSubjectKeyIdentifierHex(String pemCertificate) {

        if (StringUtils.isBlank(pemCertificate)) {
            return null;
        }
        try {
            // Parse the PEM bytes into an X509Certificate instance.
            CertificateFactory cf = CertificateFactory.getInstance(PresentationCoreConstants.JCA_X509);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pemCertificate.getBytes(StandardCharsets.UTF_8)));
            // Extract the SKI extension from the BouncyCastle certificate holder.
            SubjectKeyIdentifier ski = SubjectKeyIdentifier.fromExtensions(
                    new JcaX509CertificateHolder(cert).getExtensions());
            // Return the key identifier bytes as a lowercase hex string, or null if absent.
            return ski != null ? HexFormat.of().formatHex(ski.getKeyIdentifier()) : null;
        } catch (Exception e) {
            return null;
        }
    }
}
