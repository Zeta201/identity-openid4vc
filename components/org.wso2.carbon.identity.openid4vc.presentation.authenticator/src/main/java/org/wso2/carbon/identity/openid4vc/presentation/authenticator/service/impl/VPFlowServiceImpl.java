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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorClientException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPAuthorizationRequest;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowInitiationResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPFlowService;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.VPAuthenticatorUtil;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.OpenID4VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.management.cache.PresentationDefinitionCache;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.service.PresentationDefinitionService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Single implementation for VP flow session management.
 *
 * <p>Handles all three VP flows — authentication, standalone verification, and
 * self-registration — through a unified {@link VPSessionCache}.</p>
 */
public class VPFlowServiceImpl implements VPFlowService {

    private static final Log LOG = LogFactory.getLog(VPFlowServiceImpl.class);

    private static final long SESSION_TTL_MS =
            Long.parseLong(Constants.PROP_TIMEOUT_DEFAULT_VALUE) * 1000L;

    /**
     * Initiates a standalone VP verification or self-registration flow.
     *
     * <p>Generates a random request ID, creates a {@link VPFlowSession}, and stores it in the distributed cache.
     *
     * @param presentationDefinitionId ID of the presentation definition describing required credentials.
     * @param tenantDomain             Tenant domain under which the flow runs.
     * @return {@link VPFlowInitiationResult} containing the request ID, wallet URL, and expiry time.
     * @throws VPAuthenticatorException If either argument is blank, or session initialisation fails.
     */
    @Override
    public VPFlowInitiationResult initiate(String presentationDefinitionId, String tenantDomain)
            throws VPAuthenticatorException {

        return initiateInternal(UUID.randomUUID().toString(), presentationDefinitionId,
                tenantDomain, SESSION_TTL_MS);
    }

    /**
     * Initiates an authentication VP flow with a configurable timeout.
     *
     * <p>Used by {@link org.wso2.carbon.identity.openid4vc.presentation.authenticator.VPAuthenticator}
     * to start a login session with a per-IdP timeout.
     *
     * @param presentationDefinitionId ID of the presentation definition describing required credentials.
     * @param tenantDomain             Tenant domain under which the flow runs.
     * @param timeoutMs                Session TTL in milliseconds from now.
     * @return {@link VPFlowInitiationResult} containing the request ID, wallet URL, and expiry time.
     * @throws VPAuthenticatorException If any argument is blank or session initialisation fails.
     */
    @Override
    public VPFlowInitiationResult initiate(String requestId, String presentationDefinitionId, String tenantDomain,
            long timeoutMs) throws VPAuthenticatorException {

        return initiateInternal(requestId, presentationDefinitionId, tenantDomain, timeoutMs);
    }

    /**
     * Core flow initiation logic shared by both public {@code initiate} overloads.
     *
     * <p>Resolves tenant configuration, generates a nonce and an ephemeral EC key when
     * {@code direct_post.jwt} response mode is active, builds and caches the
     * {@link VPFlowSession}, then returns the initiation result.
     *
     * @param requestId                Unique ID for this VP request.
     * @param presentationDefinitionId ID of the presentation definition.
     * @param tenantDomain             Tenant domain.
     * @param timeoutMs                Session TTL in milliseconds from now.
     * @return {@link VPFlowInitiationResult} with wallet URL and expiry.
     * @throws VPAuthenticatorException On blank inputs, ephemeral key generation failure,
     *                                  or base URL resolution error.
     */
    private VPFlowInitiationResult initiateInternal(String requestId, String presentationDefinitionId,
            String tenantDomain, long timeoutMs)
            throws VPAuthenticatorException {

        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "presentationDefinitionId is required.");
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "tenantDomain is required.");
        }

        String nonce = UUID.randomUUID().toString();
        String pollToken = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + timeoutMs;

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        PresentationDefinition presentationDefinition =
                PresentationDefinitionCache.getInstance().get(tenantDomain, presentationDefinitionId);
        if (presentationDefinition == null) {
            try {
                presentationDefinition = getPresentationDefinitionService()
                        .getPresentationDefinitionById(presentationDefinitionId, tenantId);
            } catch (Exception e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to load presentation definition: " + presentationDefinitionId, e);
            }
            if (presentationDefinition == null) {
                throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.INVALID_REQUEST,
                        "Presentation definition not found: " + presentationDefinitionId);
            }
            PresentationDefinitionCache.getInstance().put(tenantDomain, presentationDefinition);
        }

        String baseUrl = VPAuthenticatorUtil.resolveBaseUrl();
        String responseUri = baseUrl + Constants.RESPONSE_URI_ENDPOINT;
        VPConfigService.TenantConfig tenantConfig = VPAuthenticatorUtil.loadTenantConfig(tenantDomain);
        String scheme = StringUtils.defaultIfBlank(
                tenantConfig.getClientIdScheme(), Constants.CLIENT_ID_SCHEME_X509_SAN_DNS);
        String responseMode = StringUtils.defaultIfBlank(
                tenantConfig.getResponseMode(), Constants.RESPONSE_MODE_DIRECT_POST_JWT);
        String clientId = VPAuthenticatorUtil.resolveClientIdForScheme(scheme, baseUrl, tenantDomain);

        String ephemeralPrivateKeyJwk = null;
        if (Constants.RESPONSE_MODE_DIRECT_POST_JWT.equals(responseMode)) {
            try {
                ephemeralPrivateKeyJwk = generateEphemeralECKey(requestId, Curve.P_256).toJSONString();
            } catch (JOSEException e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to generate ephemeral key for VP flow session.", e);
            }
        }

        VPFlowSession session = new VPFlowSession.Builder()
                .requestId(requestId)
                .pollToken(pollToken)
                .presentationDefinition(presentationDefinition)
                .tenantDomain(tenantDomain)
                .tenantId(tenantId)
                .status(VPFlowStatus.ACTIVE)
                .nonce(nonce)
                .ephemeralPrivateKeyJwk(ephemeralPrivateKeyJwk)
                .expiresAt(expiresAt)
                .clientId(clientId)
                .clientIdScheme(scheme)
                .responseUri(responseUri)
                .responseMode(responseMode)
                .build();
        VPSessionCache.getInstance().put(requestId, session);

        String requestUri = baseUrl + Constants.REQUEST_URI_ENDPOINT + requestId;

        String walletUrl = buildWalletUrl(clientId, requestUri);

        return new VPFlowInitiationResult(requestId, pollToken, walletUrl, requestUri, clientId, expiresAt);
    }

    @Override
    public String createAuthorizationRequestJwt(String requestId) throws VPAuthenticatorException {

        VPFlowSession session = VPSessionCache.getInstance().get(requestId);

        if (session == null) {
            throw new VPAuthenticatorClientException(VPAuthenticatorErrorCode.VP_REQUEST_NOT_FOUND,
                    "VP flow session not found: " + requestId);
        }

        PresentationDefinition pd = session.getPresentationDefinition();

        VPAuthorizationRequest vpRequest = new VPAuthorizationRequest.Builder()
                .requestId(requestId)
                .clientId(session.getClientId())
                .nonce(session.getNonce())
                .presentationDefinitionId(pd.getDefinitionId())
                .responseUri(session.getResponseUri())
                .responseMode(session.getResponseMode())
                .status(VPFlowStatus.ACTIVE)
                .expiresAt(session.getExpiresAt())
                .build();

        ECKey ephemeralPublicKey = null;
        if (StringUtils.isNotBlank(session.getEphemeralPrivateKeyJwk())) {
            try {
                ECKey keyPair = ECKey.parse(session.getEphemeralPrivateKeyJwk());
                ephemeralPublicKey = keyPair.toPublicJWK();
            } catch (Exception e) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Failed to parse ephemeral key from VP flow session.", e);
            }
        }

        return signAuthorizationRequestJwt(vpRequest, pd, session.getTenantDomain(), session.getTenantId(),
                ephemeralPublicKey, session.getClientIdScheme());
    }

    /**
     * Returns the live {@link VPFlowSession} for the given request ID, or {@code null}
     * if the session has expired or was never created.
     *
     * @param requestId Request ID returned by {@code initiate}.
     * @return The cached session, or {@code null} if absent or expired.
     */
    @Override
    public VPFlowSession getSession(String requestId) {

        return VPSessionCache.getInstance().get(requestId);
    }

    /**
     * Removes the VP flow session from the distributed cache, releasing any stored PII.
     *
     * @param requestId Request ID of the session to remove.
     */
    @Override
    public void removeSession(String requestId) {

        VPSessionCache.getInstance().remove(requestId);
    }

    /**
     * Builds and signs the OpenID4VP authorization request object as a compact JWT.
     *
     * <p>For {@code x509_san_dns} and {@code x509_hash} schemes the JWT is signed with the
     * tenant's private key (RS256 / ES256–ES512 / EdDSA depending on key type) and the
     * x5c certificate chain is embedded in the JOSE header. For the {@code redirect_uri}
     * scheme an unsigned plain JWT is returned instead.
     *
     * <p>The DCQL query, client metadata (VP formats, optional JWKS for encrypted response),
     * and optional verifier attestation are all included as JWT claims.
     *
     * @param vpRequest          Assembled authorization request data.
     * @param tenantDomain       Tenant domain used to load the signing key.
     * @param ephemeralPublicKey Ephemeral EC key embedded in {@code client_metadata.jwks}
     *                           for {@code direct_post.jwt} encrypted responses;
     *                           {@code null} for plain {@code direct_post}.
     * @param clientIdScheme     Resolved client ID scheme ({@code x509_san_dns},
     *                           {@code x509_hash}, or {@code redirect_uri}).
     * @return Compact serialized JWT.
     * @throws VPAuthenticatorException On key access, signing, or serialization failure.
     */
    private String signAuthorizationRequestJwt(
                                          VPAuthorizationRequest vpRequest,
                                          PresentationDefinition presentationDefinition,
                                          String tenantDomain,
                                          int tenantId,
                                          ECKey ephemeralPublicKey,
                                          String clientIdScheme) throws VPAuthenticatorException {

        try {

            String responseUri = vpRequest.getResponseUri();
            String scheme = StringUtils.defaultIfBlank(clientIdScheme, Constants.CLIENT_ID_SCHEME_X509_SAN_DNS);
            KeyStoreManager ksm = KeyStoreManager.getInstance(tenantId);
            KeyStore ks = IdentityKeyStoreResolver.getInstance().getKeyStore(tenantDomain, InboundProtocol.OAUTH);
            String keyAlias = VPAuthenticatorUtil.resolveSigningKeyAlias(tenantDomain);
            char[] keyPassword = resolveKeyPassword(ksm, tenantDomain);
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyAlias, keyPassword);

            if (!(privateKey instanceof ECPrivateKey)) {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "VP request signing requires an EC key but found: "
                                + (privateKey != null ? privateKey.getAlgorithm() : "null"));
            }
            ECPrivateKey ecKey = (ECPrivateKey) privateKey;
            Curve curve = Curve.forECParameterSpec(ecKey.getParams());

            // Pick the signing algorithm based on the key's EC curve
            final JWSAlgorithm jwsAlg;
            if (Curve.P_256.equals(curve)) {
                jwsAlg = JWSAlgorithm.ES256;
            } else if (Curve.P_384.equals(curve)) {
                jwsAlg = JWSAlgorithm.ES384;
            } else if (Curve.P_521.equals(curve)) {
                jwsAlg = JWSAlgorithm.ES512;
            } else {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "Unsupported EC curve: " + (curve != null ? curve.getName() : "unknown"));
            }
            JWSSigner jwsSigner = new ECDSASigner(ecKey);

            Certificate[] certChain = ks.getCertificateChain(keyAlias);
            X509Certificate cert = (X509Certificate) (certChain != null && certChain.length > 0
                    ? certChain[0] : ks.getCertificate(keyAlias));

            String certThumbprint = VPAuthenticatorUtil.computeCertHash(cert);
            final String clientId = vpRequest.getClientId();

            List<Base64> x5cChain = new ArrayList<>();
            if (certChain != null && certChain.length > 1) {
                for (Certificate c : certChain) {
                    x5cChain.add(Base64.encode(c.getEncoded()));
                }
            } else {
                x5cChain.add(Base64.encode(cert.getEncoded()));
            }

            JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlg)
                    .type(new JOSEObjectType(Constants.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                    .keyID(certThumbprint)
                    .x509CertChain(x5cChain)
                    .build();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
            claimsBuilder.issuer(clientId);

            claimsBuilder
                    .audience(OpenID4VPConstants.Protocol.REQUEST_AUDIENCE)
                    .claim(OpenID4VPConstants.RequestParams.CLIENT_ID, clientId)
                    .claim(OpenID4VPConstants.JWTClaims.CLIENT_ID_SCHEME, scheme)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_TYPE,
                            OpenID4VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_MODE, vpRequest.getResponseMode())
                    .claim(OpenID4VPConstants.RequestParams.RESPONSE_URI, responseUri)
                    .claim(OpenID4VPConstants.RequestParams.NONCE, vpRequest.getNonce())
                    .claim(OpenID4VPConstants.RequestParams.STATE, vpRequest.getRequestId())
                    .issueTime(new Date())
                    .expirationTime(new Date(vpRequest.getExpiresAt()))
                    .jwtID(UUID.randomUUID().toString());

            claimsBuilder.claim(OpenID4VPConstants.JWTClaims.DCQL_QUERY, buildDcqlQuery(presentationDefinition));

            Map<String, Object> clientMetadata = new HashMap<>();
            clientMetadata.put(Constants.METADATA_CLIENT_NAME, clientId);
            Map<String, Object> vcSdJwt = new HashMap<>();
            vcSdJwt.put(Constants.METADATA_SD_JWT_ALG_VALUES,
                    Arrays.asList(OpenID4VPConstants.Algorithms.ES256, OpenID4VPConstants.Algorithms.EDDSA,
                            OpenID4VPConstants.Algorithms.RS256));
            vcSdJwt.put(Constants.METADATA_KB_JWT_ALG_VALUES,
                    Arrays.asList(OpenID4VPConstants.Algorithms.ES256, OpenID4VPConstants.Algorithms.EDDSA));
            Map<String, Object> vpFormats = new HashMap<>();
            vpFormats.put(Constants.FORMAT_VC_SD_JWT, vcSdJwt);
            vpFormats.put(OpenID4VPConstants.VCFormats.DC_SD_JWT, vcSdJwt);
            clientMetadata.put(Constants.METADATA_VP_FORMATS, vpFormats);

            if (ephemeralPublicKey != null) {
                List<Object> keysList = new ArrayList<>();
                keysList.add(ephemeralPublicKey.toJSONObject());
                Map<String, Object> jwks = new HashMap<>();
                jwks.put(OpenID4VPConstants.ClientMetadata.KEYS, keysList);
                clientMetadata.put(OpenID4VPConstants.ClientMetadata.JWKS, jwks);
                clientMetadata.put(OpenID4VPConstants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ALG,
                        OpenID4VPConstants.Algorithms.ECDH_ES);
                clientMetadata.put(OpenID4VPConstants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ENC,
                        OpenID4VPConstants.Algorithms.A256GCM);
            }

            claimsBuilder.claim(Constants.CLAIM_CLIENT_METADATA, clientMetadata);

            JWTClaimsSet claims = claimsBuilder.build();

            JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(claims.toJSONObject()));
            jwsObject.sign(jwsSigner);
            return jwsObject.serialize();

        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Error building request object JWT for tenant="
                    + tenantDomain.replace("\r", "").replace("\n", ""), e);
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Error building request object JWT.", e);
        }
    }

    /**
     * Converts a {@link PresentationDefinition} into the DCQL query map required by
     * the OpenID4VP authorization request JWT.
     *
     * <p>Each {@link PresentationDefinition.RequestedCredential} becomes one entry in the
     * DCQL {@code credentials} array. The credential ID is derived from the credential
     * type (sanitised to a valid DCQL identifier) with a sequential numeric suffix.
     * Claim constraints are included as DCQL {@code claims} entries. A
     * {@code credential_sets} entry referencing all credential IDs is appended when
     * there is at least one credential.
     *
     * @param pd Presentation definition; {@code null} or empty produces an empty DCQL map.
     * @return DCQL query map ready to be embedded as a JWT claim.
     */
    private Map<String, Object> buildDcqlQuery(PresentationDefinition pd) {

        List<Map<String, Object>> credentials = new ArrayList<>();

        if (pd != null && pd.getRequestedCredentials() != null) {
            for (PresentationDefinition.RequestedCredential cred : pd.getRequestedCredentials()) {
                if (cred == null) {
                    continue;
                }
                Map<String, Object> dcqlCred = new HashMap<>();
                dcqlCred.put(OpenID4VPConstants.DCQL.ID, cred.getCredentialId());
                dcqlCred.put(OpenID4VPConstants.DCQL.FORMAT, cred.getFormat());

                String credType = cred.getType() != null ? cred.getType() : "";
                if (!credType.isEmpty()) {
                    Map<String, Object> meta = new HashMap<>();
                    meta.put(OpenID4VPConstants.DCQL.VCT_VALUES, Collections.singletonList(credType));
                    dcqlCred.put(OpenID4VPConstants.DCQL.META, meta);
                }

                List<Map<String, Object>> claimsList = new ArrayList<>();
                List<String> mandatoryClaimIds = new ArrayList<>();
                boolean hasOptionalClaims = false;
 
                if (cred.getClaims() != null) {
                    for (PresentationDefinition.ClaimConstraint constraint : cred.getClaims()) {
                        if (constraint == null || CollectionUtils.isEmpty(constraint.getPath())) {
                            continue;
                        }
                        Map<String, Object> claim = new HashMap<>();

                        // Every claim must have an id so it can be referenced in claim_sets.
                        // Use the explicit id when set; otherwise derive one from the path segments.
                        List<String> path = constraint.getPath() != null
                                ? constraint.getPath() : Collections.emptyList();
                        String claimId = StringUtils.isNotBlank(constraint.getId())
                                ? constraint.getId()
                                : String.join("_", path);
                        claim.put(OpenID4VPConstants.DCQL.ID, claimId);
                        claim.put(OpenID4VPConstants.DCQL.PATH, path);

                        if (!CollectionUtils.isEmpty(constraint.getAllowedValues())) {
                            claim.put(OpenID4VPConstants.DCQL.VALUES, constraint.getAllowedValues());
                        }

                        claimsList.add(claim);

                        if (constraint.isMandatory()) {
                            mandatoryClaimIds.add(claimId);
                        } else {
                            hasOptionalClaims = true;
                        }
                    }
                }
                if (!claimsList.isEmpty()) {
                    dcqlCred.put(OpenID4VPConstants.DCQL.CLAIMS, claimsList);
                }

                if (hasOptionalClaims && !mandatoryClaimIds.isEmpty()) {
                    List<String> allClaimIds = new ArrayList<>();
                    for (Map<String, Object> claimMap : claimsList) {
                        allClaimIds.add((String) claimMap.get(OpenID4VPConstants.DCQL.ID));
                    }
                    List<List<String>> autoSets = new ArrayList<>();
                    autoSets.add(allClaimIds);
                    autoSets.add(mandatoryClaimIds);
                    dcqlCred.put(OpenID4VPConstants.DCQL.CLAIM_SETS, autoSets);
                }

                // HAIP §5: include trusted_authorities / aki when trusted CAs are configured.
                List<String> credTrustedCas = cred.getTrustedCas();
                if (credTrustedCas != null && !credTrustedCas.isEmpty()) {
                    List<String> allAkiValues = new ArrayList<>();
                    for (String trustedCaPem : credTrustedCas) {
                        allAkiValues.addAll(resolveTrustAnchorAkiValues(trustedCaPem));
                    }
                    if (!allAkiValues.isEmpty()) {
                        Map<String, Object> trustedAuthority = new HashMap<>();
                        trustedAuthority.put(OpenID4VPConstants.DCQL.TRUSTED_AUTHORITY_TYPE,
                                OpenID4VPConstants.DCQL.TRUSTED_AUTHORITY_TYPE_AKI);
                        trustedAuthority.put(OpenID4VPConstants.DCQL.TRUSTED_AUTHORITY_VALUES, allAkiValues);
                        dcqlCred.put(OpenID4VPConstants.DCQL.TRUSTED_AUTHORITIES,
                                Collections.singletonList(trustedAuthority));
                    }
                }

                credentials.add(dcqlCred);
            }
        }

        Map<String, Object> dcql = new HashMap<>();
        dcql.put(OpenID4VPConstants.DCQL.CREDENTIALS, credentials);

        if (!credentials.isEmpty()) {
            List<String> allCredIds = new ArrayList<>();
            for (Map<String, Object> cred : credentials) {
                allCredIds.add((String) cred.get(OpenID4VPConstants.DCQL.ID));
            }

            Map<String, Object> credSet = new HashMap<>();
            credSet.put(OpenID4VPConstants.DCQL.OPTIONS, Collections.singletonList(allCredIds));
            dcql.put(OpenID4VPConstants.DCQL.CREDENTIAL_SETS, Collections.singletonList(credSet));
        }

        return dcql;
    }

    /**
     * Computes the base64url-encoded SubjectKeyIdentifier (SKI) of the configured trusted root CA
     * for use as the {@code aki} value in the DCQL {@code trusted_authorities} field
     * (HAIP §5 / OID4VP §6.1.1.1).
     *
     * <p>Uses the per-credential {@code trustedCaPem} field rather than the server-wide trust store,
     * so this works identically on Asgardeo (SaaS) and on-premises deployments.
     *
     * <p>Returns an empty list (and logs a warning) if the PEM is absent or unparseable —
     * the DCQL request is still sent but without the {@code trusted_authorities} hint.
     *
     * @param trustedCaPem PEM-encoded root CA certificate from the credential configuration.
     */
    private List<String> resolveTrustAnchorAkiValues(String trustedCaPem) {

        if (trustedCaPem == null || trustedCaPem.isBlank()) {
            LOG.warn("trustedCaPem is not configured for this X5C credential; "
                    + "trusted_authorities will be omitted from DCQL.");
            return Collections.emptyList();
        }
        try {
            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(
                            trustedCaPem.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            String ski = extractSkiBase64url(caCert);
            if (ski == null) {
                LOG.warn("Trusted CA certificate has no SubjectKeyIdentifier extension; "
                        + "trusted_authorities will be omitted from DCQL.");
                return Collections.emptyList();
            }
            return Collections.singletonList(ski);
        } catch (Exception e) {
            LOG.warn("Could not parse trustedCaPem for trusted_authorities computation: "
                    + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Extracts the raw SubjectKeyIdentifier bytes from a certificate's extension and
     * returns them base64url-encoded (no padding).
     *
     * <p>The SubjectKeyIdentifier extension value is DER-encoded as:
     * {@code OCTET STRING { OCTET STRING { key_id_bytes } }}. This method handles
     * short-form DER lengths (< 128 bytes), which covers all standard SHA-1 key IDs.
     *
     * @return base64url-encoded SKI, or {@code null} if the extension is absent or malformed.
     */
    private static String extractSkiBase64url(X509Certificate cert) {

        byte[] extValue = cert.getExtensionValue("2.5.29.14");
        if (extValue == null || extValue.length < 5) {
            return null;
        }
        try {
            // extValue layout: [0x04][outerLen][0x04][innerLen][ski_bytes...]
            // Both lengths are assumed short-form (1 byte, value < 0x80).
            if (extValue[0] != 0x04 || extValue[2] != 0x04) {
                return null;
            }
            int innerLen = extValue[3] & 0xFF;
            if (extValue.length < 4 + innerLen) {
                return null;
            }
            byte[] ski = Arrays.copyOfRange(extValue, 4, 4 + innerLen);
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ski);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns the {@link PresentationDefinitionService} from the OSGi service holder,
     * throwing a server exception if it has not yet been bound.
     *
     * @return Non-null presentation definition service.
     * @throws VPAuthenticatorException If the service is unavailable.
     */
    private PresentationDefinitionService getPresentationDefinitionService() throws VPAuthenticatorException {

        PresentationDefinitionService service = VPDataHolder.getPresentationDefinitionService();
        if (service == null) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Presentation definition service is not initialized.");
        }
        return service;
    }

    /**
     * Resolves the private key password for the given tenant's keystore.
     *
     * <p>For the super tenant the password is read from {@code deployment.toml} via
     * {@link ServerConfiguration}. For other tenants it is retrieved through
     * {@link KeyStoreManager#getPrivateKeyPassword}.
     *
     * @param ksm          KeyStoreManager instance for the tenant.
     * @param tenantDomain Tenant domain.
     * @return Key password as a {@code char[]}; empty array if not configured.
     * @throws VPAuthenticatorException If the password cannot be retrieved.
     */
    private char[] resolveKeyPassword(KeyStoreManager ksm, String tenantDomain)
            throws VPAuthenticatorException {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            String pwd = ServerConfiguration.getInstance().getFirstProperty(
                    RegistryResources.SecurityManagement.SERVER_PRIVATE_KEY_PASSWORD);
            return pwd != null ? pwd.toCharArray() : new char[0];
        }
        try {
            char[] pwd = ksm.getPrivateKeyPassword(tenantDomain.replace(".", "-") + ".jks");
            return pwd != null ? pwd : new char[0];
        } catch (CarbonException e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to retrieve keystore password for tenant: " + tenantDomain, e);
        }
    }

    private static ECKey generateEphemeralECKey(String keyId, Curve curve) throws JOSEException {

        return new ECKeyGenerator(curve).keyID(keyId).generate();
    }

    /**
     * Builds the deep-link wallet URL ({@code openid4vp://?client_id=…&request_uri=…})
     * that is displayed as a QR code or universal link for the holder's wallet app.
     *
     * @param clientId   The verifier's resolved client ID.
     * @param requestUri The request URI where the wallet fetches the signed request object.
     * @return URL-encoded wallet deep-link string.
     */
    private String buildWalletUrl(String clientId, String requestUri) {

        String encodedClientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String encodedRequestUri = URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
        return OpenID4VPConstants.Protocol.OPENID4VP_SCHEME + "?" + OpenID4VPConstants.RequestParams.CLIENT_ID
                + "=" + encodedClientId + "&" + OpenID4VPConstants.RequestParams.REQUEST_URI
                + "=" + encodedRequestUri;
    }
}
