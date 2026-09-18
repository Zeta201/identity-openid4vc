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

package org.wso2.carbon.identity.openid4vc.presentation.core.service.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheEntry;
import org.wso2.carbon.identity.openid4vc.presentation.core.cache.VPSessionCacheKey;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.PresentationCoreConstants;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationRequestResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.PresentationSubmissionDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VPSessionStatusRespDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VPVerificationResultDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreClientException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;
import org.wso2.carbon.identity.openid4vc.presentation.core.internal.PresentationCoreDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSessionStatus;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPTenantConfig;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationRequestService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationSessionService;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.util.DcqlUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreAuditLogger;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreExceptionHandler;
import org.wso2.carbon.identity.openid4vc.presentation.core.util.PresentationCoreUtil;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.lang.reflect.Type;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;


/**
 * Core implementation of the OpenID4VP presentation flow.
 *
 * <p>Covers the full server-side lifecycle of a VP request:
 * session initiation, signed request JWT construction, wallet response parsing
 * (both {@code direct_post} and {@code direct_post.jwt}), verification result
 * recording, and session status tracking.
 */
public class PresentationCoreServiceImpl implements PresentationSessionService, PresentationRequestService {

    private static final Log LOG = LogFactory.getLog(PresentationCoreServiceImpl.class);
    private static final PresentationCoreAuditLogger AUDIT_LOGGER = PresentationCoreAuditLogger.getInstance();
    // Maximum time (2 minutes) a VP session remains active waiting for the wallet to submit a response.
    private static final long SESSION_TIMEOUT_MS = 120_000L;
    private static final Gson GSON = new GsonBuilder().create();
    private static final Type VP_TOKEN_TYPE = new TypeToken<Map<String, Object>>() { }.getType();

    /**
     * Initiates a new VP session for the given presentation definition.
     *
     * <p>The flow is:
     * <ol>
     *   <li>Validate inputs and load the presentation definition for the tenant.</li>
     *   <li>Resolve the tenant's VP config (client ID scheme, response mode) and derive the
     *       {@code client_id} and endpoint URLs.</li>
     *   <li>Generate an ephemeral EC key pair when {@code direct_post.jwt} is required so the
     *       wallet can encrypt its response to this server.</li>
     *   <li>Persist the session in the distributed cache and return the request metadata to the
     *       caller, who uses {@code walletUrl} to redirect the user's wallet.</li>
     * </ol>
     *
     * @param presentationDefinitionId ID of the presentation definition that describes which
     *                                 credentials the wallet must present.
     * @param tenantDomain             tenant under which the session is created.
     * @return a DTO containing the {@code requestId}, wallet deep-link URL, {@code request_uri},
     *         {@code client_id}, and session expiry timestamp.
     * @throws PresentationCoreException if the presentation definition is not found, the tenant
     *                                   config cannot be read, or URL/key generation fails.
     */
    @Override
    public PresentationRequestResponseDTO startPresentationSession(String presentationDefinitionId, String tenantDomain)
            throws PresentationCoreException {

        // Reject blank inputs before any state is created.
        if (StringUtils.isBlank(presentationDefinitionId)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        if (StringUtils.isBlank(tenantDomain)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }

        // Unique session handle — used as the cache key, JWT kid, and state parameter.
        String requestId = UUID.randomUUID().toString();
        // One-time value that binds the VP token to this specific presentation request.
        String nonce = UUID.randomUUID().toString();
        // Absolute epoch timestamp after which the session is considered expired.
        long expiresAt = System.currentTimeMillis() + SESSION_TIMEOUT_MS;
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        // Load the presentation definition.
        PresentationDefinition presentationDefinition =
                loadPresentationDefinition(presentationDefinitionId, tenantId);

        // Build the URL the wallet posts the VP token to after the user approves the request.
        String responseUri = PresentationCoreUtil.buildResponseUri(tenantDomain);
        // Get the tenant-level config that controls the client_id scheme and response mode.
        VPTenantConfig vpTenantConfig = PresentationCoreDataHolder.getInstance()
                .getVpConfigService().getVPConfig(tenantDomain);
        String scheme = vpTenantConfig.getClientIdScheme();
        String responseMode = vpTenantConfig.getResponseMode();
        // Derive the client_id value from the configured scheme — either a SAN DNS name or a cert hash.
        String clientId = PresentationCoreUtil.buildClientId(scheme, tenantDomain);
        // EC P-256 key pair required only for direct_post.jwt to let the wallet ECDH-encrypt its response.
        // Public half is embedded in the request JWT; private half is kept in the session for decryption.
        String ephemeralPrivateKeyJwk = PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT.equals(responseMode)
                ? generateEphemeralKey(requestId)
                : null;
        // URL the wallet fetches to retrieve the signed presentation request JWT.
        String requestUri = PresentationCoreUtil.buildRequestUri(tenantDomain, requestId);
        // Deep-link URL that encodes client_id and request_uri for the wallet to scan/open.
        String walletUrl = PresentationCoreUtil.buildWalletUrl(clientId, requestUri);

        // Build the session object with all parameters the server needs to process
        // the wallet's response and verify the VP token.
        VPSession session = new VPSession.Builder()
                .presentationDefinition(presentationDefinition)
                .tenantDomain(tenantDomain)
                .tenantId(tenantId)
                .status(VPSessionStatus.ACTIVE)
                .nonce(nonce)
                .ephemeralPrivateKeyJwk(ephemeralPrivateKeyJwk)
                .expiresAt(expiresAt)
                .clientId(clientId)
                .clientIdScheme(scheme)
                .responseUri(responseUri)
                .responseMode(responseMode)
                .walletUrl(walletUrl)
                .build();

        // Store the session in the db backed session cache keyed by requestId so subsequent
        // wallet requests (fetch request JWT, post VP token) can retrieve it.
        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), tenantId);
        AUDIT_LOGGER.logVPSessionInitiated(requestId, presentationDefinition, tenantDomain, responseMode);

        return new PresentationRequestResponseDTO(requestId, walletUrl, requestUri, clientId, expiresAt);
    }

    /**
     * Loads and validates the presentation definition for the given ID and tenant.
     *
     * @param identifier       presentation definition ID to look up.
     * @param tenantId numeric tenant ID used to scope the lookup.
     * @return the matching {@link PresentationDefinition}; never {@code null}.
     * @throws PresentationCoreException if the lookup fails or no definition exists for the given ID.
     */
    private PresentationDefinition loadPresentationDefinition(String identifier, int tenantId)
            throws PresentationCoreException {

        PresentationDefinition definition;
        try {
            // Fetch from the persistent store; returns null if the ID is not registered for this tenant.
            definition = PresentationCoreDataHolder.getInstance().getPresentationDefinitionManager()
                    .getPresentationDefinitionById(identifier, tenantId);
        } catch (PresentationManagementException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.PRESENTATION_DEFINITION_ERROR, e);
        }
        // Surface null result as a not found client error.
        if (definition == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.PRESENTATION_DEFINITION_NOT_FOUND, identifier);
        }
        return definition;
    }

    /**
     * Generates a one-time EC P-256 key pair for ECDH encryption of the wallet's VP token response.
     *
     * <p>The {@code requestId} is set as the key ID ({@code kid}) so the server can look up
     * the matching private key from the session when the encrypted response arrives.
     *
     * @param requestId session request ID used as the key's {@code kid}.
     * @return the generated private key serialized as a JWK JSON string.
     * @throws PresentationCoreServerException if key generation fails.
     */
    private String generateEphemeralKey(String requestId) throws PresentationCoreServerException {

        try {
            // Generate a P-256 key pair as required by the OpenID4VP spec for ECDH-ES key agreement.
            return new ECKeyGenerator(Curve.P_256).keyID(requestId).generate().toJSONString();
        } catch (JOSEException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.EPHEMERAL_KEY_ERROR, e);
        }
    }

    /**
     * Builds the signed OpenID4VP presentation request JWT for the given session.
     *
     * <p>Validates the session is present, belongs to the requesting tenant, and is still
     * active before assembling the JWT claims and signing with
     * {@link #signWithTenantKey}.
     *
     * @param requestId    VP session ID returned by {@link #startPresentationSession}.
     * @param tenantDomain tenant that owns the session.
     * @return the compact-serialized signed presentation request JWT.
     * @throws PresentationCoreException if the session is not found, expired, or signing fails.
     */
    @Override
    public String buildPresentationRequest(String requestId, String tenantDomain) throws PresentationCoreException {

        // Resolve the tenant ID.
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Look up the session from the distributed cache using the request ID.
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Return NOT_FOUND (not a tenant-mismatch error) to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Mark the session failed and reject if the session is not active.
        if (session.getStatus() != VPSessionStatus.ACTIVE) {
            handleSessionFailed(requestId, tenantDomain, PresentationCoreErrorCode.VP_REQUEST_EXPIRED.getErrorType(),
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED.getDescription());
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED);
        }
        // Assemble the JWT claims from the session and sign with the tenant's EC key.
        JWTClaimsSet claims = buildPresentationRequestClaims(session);
        return signWithTenantKey(claims, tenantDomain, tenantId);
    }

    /**
     * Signs the given JWT claims with the tenant's EC private key.
     *
     * <p>Loads the tenant's OAuth keystore, resolves the EC private key and signing certificate,
     * builds the JWS header with type {@code oauth-authz-req+jwt}, the certificate hash as {@code kid},
     * and the full chain as {@code x5c}, then signs with ES256.
     *
     * @param claims       JWT claims to sign.
     * @param tenantDomain tenant whose keystore is used for signing.
     * @param tenantId     numeric tenant ID used to obtain the keystore manager.
     * @return the compact-serialized signed JWS string.
     * @throws PresentationCoreException if key/cert loading or signing fails.
     */
    private String signWithTenantKey(JWTClaimsSet claims, String tenantDomain, int tenantId)
            throws PresentationCoreException {

        try {
            // Load the keystore manager and OAuth keystore for the tenant.
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            KeyStore keyStore = IdentityKeyStoreResolver.getInstance()
                    .getKeyStore(tenantDomain, InboundProtocol.OAUTH);
            // Resolve the EC key alias registered for this tenant.
            String keyAlias = PresentationCoreUtil.resolveSigningKeyAlias(tenantDomain);
            // Load the EC private key using the tenant keystore password.
            ECPrivateKey ecKey = PresentationCoreUtil.loadEcPrivateKey(keyStore, keyAlias,
                    PresentationCoreUtil.resolveKeyPassword(keyStoreManager, tenantDomain));
            // Resolve the signing certificate and chain for the JWS x5c header.
            X509Certificate certificate = PresentationCoreUtil.resolveSigningCertificate(keyStore, keyAlias);
            Certificate[] certificateChain = keyStore.getCertificateChain(keyAlias);
            // Build the JWS header: type, kid (cert hash), and x5c (full chain).
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(PresentationCoreConstants.JOSE_TYPE_OAUTH_AUTHZ_REQ))
                    .keyID(PresentationCoreUtil.computeCertHash(certificate))
                    .x509CertChain(PresentationCoreUtil.buildX5cChain(certificateChain, certificate))
                    .build();
            // Sign the claims with the tenant's EC private key.
            JWSObject jws = new JWSObject(header, new Payload(claims.toJSONObject()));
            jws.sign(new ECDSASigner(ecKey));
            return jws.serialize();
        } catch (GeneralSecurityException | JOSEException | IdentityKeyStoreResolverException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_ERROR, e);
        }
    }

    /**
     * Builds the JWT claims set for the VP request.
     *
     * <p>Populates standard OAuth/OpenID4VP parameters from the session: issuer, audience,
     * {@code client_id}, {@code response_type}, {@code response_mode}, {@code response_uri},
     * {@code nonce}, {@code state}, and the DCQL query that describes the requested credentials.
     * When {@code direct_post.jwt} is configured, the ephemeral public key is included in
     * {@code client_metadata} so the wallet can perform ECDH-ES encryption.
     *
     * @param session active VP session containing all parameters for this VP request.
     * @return the assembled {@link JWTClaimsSet} ready to be signed.
     * @throws PresentationCoreServerException if the ephemeral public key cannot be parsed.
     */
    private static JWTClaimsSet buildPresentationRequestClaims(VPSession session) throws
            PresentationCoreServerException {

        String clientId = session.getClientId();
        return new JWTClaimsSet.Builder()
                .issuer(clientId)
                .audience(Constants.Protocol.REQUEST_AUDIENCE)
                .claim(Constants.RequestParams.CLIENT_ID, clientId)
                .claim(Constants.JWTClaims.CLIENT_ID_SCHEME, session.getClientIdScheme())
                .claim(Constants.RequestParams.RESPONSE_TYPE, Constants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                .claim(Constants.RequestParams.RESPONSE_MODE, session.getResponseMode())
                .claim(Constants.RequestParams.RESPONSE_URI, session.getResponseUri())
                .claim(Constants.RequestParams.NONCE, session.getNonce())
                .claim(Constants.RequestParams.STATE, session.getRequestId())
                .issueTime(new Date())
                .expirationTime(new Date(session.getExpiresAt()))
                .jwtID(UUID.randomUUID().toString())
                .claim(Constants.JWTClaims.DCQL_QUERY,
                        DcqlUtil.buildDcqlQuery(session.getPresentationDefinition()))
                .claim(PresentationCoreConstants.CLAIM_CLIENT_METADATA,
                        DcqlUtil.buildClientMetadata(clientId,
                                PresentationCoreUtil.resolveEphemeralPublicKey(session)))
                .build();
    }

    /**
     * Retrieves an active VP session by request ID.
     *
     * <p>Looks up the session from the distributed cache and verifies it has not expired.
     * Expired sessions are evicted from the cache before the error is returned so they
     * do not linger and consume memory.
     *
     * @param requestId    VP session ID issued by {@link #startPresentationSession}.
     * @param tenantDomain tenant that owns the session.
     * @return the active {@link VPSession}.
     * @throws PresentationCoreException if the session is not found or has expired.
     */
    @Override
    public VPSession getPresentationSession(String requestId, String tenantDomain) throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Fetch the session from the cache; returns null if absent or already evicted.
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Evict the expired session before throwing so it does not remain in cache.
        if (System.currentTimeMillis() > session.getExpiresAt()) {
            VPSessionCache.getInstance().clearCacheEntry(
                    new VPSessionCacheKey(requestId), tenantId);
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_EXPIRED);
        }
        return session;
    }

    /**
     * Looks up a VP session from the cache by request ID and tenant.
     *
     * @param requestId session ID issued by {@link #startPresentationSession}.
     * @param tenantId  numeric tenant ID used to scope the cache lookup.
     * @return the cached {@link VPSession}, or {@code null} if absent or already evicted.
     */
    private VPSession getSessionFromCache(String requestId, int tenantId) {

        VPSessionCacheEntry entry = VPSessionCache.getInstance().getValueFromCache(
                new VPSessionCacheKey(requestId), tenantId);
        return entry != null ? entry.getSession() : null;
    }


    /**
     * Validates that the wallet's response format matches the mode configured for the session.
     *
     * <p>Callers pass {@code encryptedResponseExpected = true} when they received a JWE
     * ({@code direct_post.jwt}) and {@code false} when they received a plain form post
     * ({@code direct_post}). A mismatch marks the session as failed before throwing so
     * the session does not remain active.
     *
     * @param configuredResponseMode    response mode stored on the session ({@code direct_post} or
     *                                  {@code direct_post.jwt}).
     * @param encryptedResponseExpected {@code true} if the caller received a JWE-encrypted response.
     * @throws PresentationCoreClientException if the actual response format does not match the session config.
     */
    private void validateResponseMode(String configuredResponseMode, boolean encryptedResponseExpected)
            throws PresentationCoreClientException {

        // Check whether the session was configured to require an encrypted (direct_post.jwt) response.
        boolean isEncryptedResponseMode = PresentationCoreConstants.RESPONSE_MODE_DIRECT_POST_JWT
                .equals(configuredResponseMode);
        // Fail the session and reject if the response format does not match the configured mode.
        if (isEncryptedResponseMode != encryptedResponseExpected) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.RESPONSE_MODE_MISMATCH);
        }
    }

    /**
     * Dispatches the wallet's form-encoded response to the correct parser based on response format.
     *
     * <p>A {@code direct_post.jwt} response carries a {@code response} parameter containing a JWE;
     * a plain {@code direct_post} response omits it and uses individual form fields instead.
     *
     * @param formParams   decoded form parameters from the wallet's HTTP POST body.
     * @param tenantDomain tenant that owns the VP session.
     * @return a {@link PresentationSubmissionDTO} containing the request ID and extracted credential tokens,
     *         or an error if the wallet reported one.
     * @throws PresentationCoreException if parsing or decryption fails.
     */
    @Override
    public PresentationSubmissionDTO parsePresentationSubmission(Map<String, List<String>> formParams,
                                                                 String tenantDomain)
            throws PresentationCoreException {

        // Presence of the `response` parameter signals a direct_post.jwt (JWE-encrypted) response.
        String responseParam = PresentationCoreUtil
                .extractFirstFormParam(formParams, Constants.ResponseParams.RESPONSE);
        if (StringUtils.isNotBlank(responseParam)) {
            return parseDirectPostJwt(responseParam, tenantDomain);
        }
        // Fall back to plain direct_post — individual form fields carry the VP token.
        return parseDirectPost(formParams, tenantDomain);
    }

    /**
     * Parses a {@code direct_post.jwt} response: decrypts the JWE with the session's ephemeral
     * private key and extracts the VP token or wallet-reported error from the inner claims.
     *
     * <p>The JWE {@code kid} header identifies the session (and the matching ephemeral key).
     * The inner payload may be a signed JWT or a plain JSON object; both are handled.
     *
     * @param responseParam compact-serialized JWE sent by the wallet in the {@code response} field.
     * @param tenantDomain  tenant that owns the VP session.
     * @return a {@link PresentationSubmissionDTO} with the credential tokens or wallet error.
     * @throws PresentationCoreException if the JWE cannot be parsed, decrypted, or the session is invalid.
     */
    private PresentationSubmissionDTO parseDirectPostJwt(String responseParam, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Declare requestId before the try block so it is accessible in the catch for session failure recording.
        String requestId = null;
        try {
            // Parse the compact JWE to extract headers before decryption.
            JWEObject jweObject = JWEObject.parse(responseParam);
            // Extract the request ID from the JWE kid header — the wallet echoes back the ephemeral key ID.
            requestId = jweObject.getHeader().getKeyID();
            if (StringUtils.isBlank(requestId)) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            // Retrieve the session to obtain the ephemeral private key for decryption.
            VPSession session = getSessionFromCache(requestId, tenantId);
            if (session == null || StringUtils.isBlank(session.getEphemeralPrivateKeyJwk())) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            // Verify the wallet used the encrypted response mode this session was configured for.
            validateResponseMode(session.getResponseMode(), true);
            // Decrypt the JWE and extract claims from the inner payload.
            JWTClaimsSet claims = PresentationCoreUtil.decryptJweResponse(
                    jweObject, session.getEphemeralPrivateKeyJwk());
            // Build and return the submission DTO from the decrypted claims.
            return buildSubmissionFromClaims(claims);

        } catch (PresentationCoreException e) {
            // Mark the session failed for any protocol-level error (e.g. response mode mismatch, invalid session).
            handleSessionFailed(requestId, tenantDomain, e.getErrorType(), e.getDescription());
            throw e;
        } catch (ParseException | JOSEException e) {
            // Mark the session failed before throwing so it does not remain active after a decryption failure.
            handleSessionFailed(requestId, tenantDomain,
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR.getErrorType(),
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR.getDescription());
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.WALLET_RESPONSE_DECRYPTION_ERROR, e);
        }
    }

    /**
     * Builds a {@link PresentationSubmissionDTO} from the decrypted JWT claims.
     *
     * <p>Returns an error submission immediately if the claims carry an {@code error} field.
     * Otherwise extracts and flattens the {@code vp_token} map into credential tokens.
     *
     * @param claims JWT claims from the decrypted wallet response.
     * @return the assembled {@link PresentationSubmissionDTO}.
     * @throws PresentationCoreException if the {@code state} claim is missing.
     * @throws ParseException            if a claim value cannot be parsed.
     */
    private PresentationSubmissionDTO buildSubmissionFromClaims(JWTClaimsSet claims)
            throws PresentationCoreException, ParseException {

        // Extract the request ID from the state claim.
        String requestId = claims.getStringClaim(Constants.ResponseParams.STATE);
        if (StringUtils.isBlank(requestId)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        // Surface a wallet-reported error immediately without attempting to extract a VP token.
        String error = claims.getStringClaim(Constants.ResponseParams.ERROR);
        if (StringUtils.isNotBlank(error)) {
            return PresentationSubmissionDTO.builder()
                    .requestId(requestId)
                    .error(error)
                    .errorDescription(claims.getStringClaim(Constants.ResponseParams.ERROR_DESCRIPTION))
                    .build();
        }
        // Extract the VP token map and flatten it to a credential-identifier → token mapping.
        Map<String, Object> vpTokenMap = claims.getJSONObjectClaim(Constants.ResponseParams.VP_TOKEN);
        return PresentationSubmissionDTO.builder()
                .requestId(requestId)
                .credentialTokens(vpTokenMap != null ? PresentationCoreUtil.flattenVpTokenMap(vpTokenMap) : null)
                .build();
    }

    /**
     * Parses a plain {@code direct_post} response where the VP token and state are sent as
     * individual form fields rather than inside an encrypted JWE.
     *
     * <p>If the wallet posted an error field, the error is returned immediately without
     * attempting to read the VP token. When a session is found, its response mode is validated
     * to confirm {@code direct_post.jwt} was not expected.
     *
     * @param formParams   decoded form parameters from the wallet's HTTP POST body.
     * @param tenantDomain tenant that owns the VP session.
     * @return a {@link PresentationSubmissionDTO} with the credential tokens or wallet error.
     * @throws PresentationCoreException if the VP token JSON is malformed or the response mode mismatches.
     */
    private PresentationSubmissionDTO parseDirectPost(Map<String, List<String>> formParams, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Extract the session ID the wallet echoes back in the `state` parameter.
        String requestId = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.STATE);
        // Check for a wallet-reported error before attempting VP token extraction.
        String error = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.ERROR);
        if (StringUtils.isNotBlank(error)) {
            return PresentationSubmissionDTO.builder()
                    .requestId(requestId)
                    .error(error)
                    .errorDescription(PresentationCoreUtil.extractFirstFormParam(
                            formParams, Constants.ResponseParams.ERROR_DESCRIPTION))
                    .build();
        }
        // Verify the session was not configured to require an encrypted response.
        if (StringUtils.isNotBlank(requestId)) {
            VPSession session = getSessionFromCache(requestId, tenantId);
            if (session == null) {
                throw PresentationCoreExceptionHandler.handleClientException(
                        PresentationCoreErrorCode.INVALID_REQUEST);
            }
            validateResponseMode(session.getResponseMode(), false);
        }
        // Parse the VP token JSON and flatten to a credential-identifier → token mapping.
        String vpToken = PresentationCoreUtil.extractFirstFormParam(formParams, Constants.ResponseParams.VP_TOKEN);
        try {
            Map<String, Object> rawMap = GSON.fromJson(vpToken, VP_TOKEN_TYPE);
            return PresentationSubmissionDTO.builder()
                    .requestId(requestId)
                    .credentialTokens(PresentationCoreUtil.flattenVpTokenMap(rawMap))
                    .build();
        } catch (JsonSyntaxException e) {
            // Mark the session failed before throwing so it does not remain active after a malformed VP token.
            handleSessionFailed(requestId, tenantDomain,
                    PresentationCoreErrorCode.INVALID_VP_TOKEN.getErrorType(),
                    PresentationCoreErrorCode.INVALID_VP_TOKEN.getDescription());
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }
    }

    /**
     * Constructs a {@link VerificationRequestDTO} from a parsed wallet submission, ready to be
     * forwarded to the credential verifier.
     *
     * <p>Validates the submission, resolves the session, and extracts the credential token that
     * matches the first credential descriptor in the presentation definition.
     *
     * @param submission   parsed wallet response containing the request ID and credential tokens.
     * @param tenantDomain tenant that owns the VP session.
     * @return a {@link VerificationRequestDTO} carrying the credential token, descriptor,
     *         session nonce, and client ID needed by the verifier.
     * @throws PresentationCoreException if the submission is invalid, the session is not found
     *                                   or not active, or the expected credential token is absent.
     */
    @Override
    public VerificationRequestDTO buildVerificationRequest(PresentationSubmissionDTO submission, String tenantDomain)
            throws PresentationCoreException {

        String requestId = submission.getRequestId();
        // Reject submissions that carry no session reference.
        if (StringUtils.isBlank(requestId)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        // Reject submissions that carry no credential tokens before hitting the cache.
        if (submission.getCredentialTokens() == null || submission.getCredentialTokens().isEmpty()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Look up the session from the cache.
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Reject if the session has already been consumed or expired.
        if (session.getStatus() != VPSessionStatus.ACTIVE) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        // Load the presentation definition to determine which credential type was requested.
        PresentationDefinition definition = session.getPresentationDefinition();
        if (CollectionUtils.isEmpty(definition.getCredentials())) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_REQUEST);
        }
        // Resolve the first credential descriptor — currently ony single credential flows are supported.
        Credential credential = definition.getCredentials().getFirst();
        // Extract the credential token that matches the descriptor's identifier from the submission.
        String credentialToken = submission.getCredentialTokens().get(credential.getIdentifier());
        if (StringUtils.isBlank(credentialToken)) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.INVALID_VP_TOKEN);
        }
        // Build the verification request with the token, descriptor, nonce, and client ID.
        return new VerificationRequestDTO(credentialToken, credential,
                session.getNonce(), session.getClientId());
    }
    
    /**
     * Marks a VP session as successfully verified and persists the verification result.
     *
     * <p>Attaches the verifier's response to the session, transitions the status to
     * {@link VPSessionStatus#VERIFIED}, and writes the updated session back to the cache
     * so status-polling callers see the terminal state.
     *
     * @param requestId            VP session ID to finalize.
     * @param tenantDomain         tenant that owns the session.
     * @param verificationResponse result from the credential verifier; may be {@code null}
     *                             if the verifier produced no structured response.
     */
    @Override
    public void handleSessionVerified(String requestId, String tenantDomain,
                                      VerificationResponseDTO verificationResponse)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        // Get the session from cache.
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            LOG.warn("Session not found when finalizing as verified: " + requestId);
            return;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Set the verifier's result and transition the session to its verified state.
        session.setVerificationResponse(verificationResponse);
        session.setStatus(VPSessionStatus.VERIFIED);
        // Write the updated session back so status-polling callers see the result immediately.
        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), tenantId);
        AUDIT_LOGGER.logVPCredentialVerified(requestId,
                verificationResponse != null ? verificationResponse.getCredentialId() : null,
                session.getTenantDomain());
    }

    /**
     * Marks a VP session as failed, records the error details, and persists the terminal state.
     *
     * <p>No-ops silently when the request ID is blank or the session is not found.
     * Sessions already in a terminal state ({@link VPSessionStatus#VERIFIED} or
     * {@link VPSessionStatus#FAILED}) are left unchanged to avoid overwriting a
     * concurrent success with a late-arriving error.
     *
     * @param requestId        VP session ID to mark as failed.
     * @param tenantDomain     tenant that owns the session.
     * @param errorType        protocol-level error type to store on the session.
     * @param errorDescription human-readable description of the failure.
     */
    @Override
    public void handleSessionFailed(String requestId, String tenantDomain, String errorType,
                                    String errorDescription) throws PresentationCoreException {

        if (StringUtils.isBlank(requestId)) {
            return;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            LOG.warn("Session not found when finalizing as failed: " + requestId);
            return;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        // Skip if the session has already reached a terminal state to avoid overwriting a concurrent success.
        if (session.getStatus() == VPSessionStatus.VERIFIED || session.getStatus() == VPSessionStatus.FAILED) {
            return;
        }
        // Transition the session to failed and record the error details for status-polling callers.
        session.setStatus(VPSessionStatus.FAILED);
        session.setErrorType(errorType);
        session.setErrorDescription(errorDescription);
        // Write the updated session back so status-polling callers see the failure immediately.
        VPSessionCache.getInstance().addToCache(new VPSessionCacheKey(requestId),
                new VPSessionCacheEntry(session), tenantId);
        AUDIT_LOGGER.logVPCredentialVerificationFailed(requestId, errorType, errorDescription,
                session.getTenantDomain());
    }

    /**
     * Returns the current result of a VP session, including its status, verification response,
     * and any error details recorded during the flow.
     *
     * @param requestId    VP session ID issued by {@link #startPresentationSession}.
     * @param tenantDomain tenant that owns the session.
     * @return the session result DTO, or {@code null} if no session exists for the given request ID.
     */
    @Override
    public VPSessionStatusRespDTO getVerificationSessionStatus(String requestId, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            return null;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        VPSessionStatusRespDTO dto = new VPSessionStatusRespDTO();
        dto.setRequestId(session.getRequestId());
        dto.setStatus(session.getStatus());
        dto.setExpiresAt(session.getExpiresAt());
        dto.setErrorType(session.getErrorType());
        return dto;
    }

    @Override
    public VPVerificationResultDTO getPresentationSessionResult(String requestId, String tenantDomain)
            throws PresentationCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        VPSession session = getSessionFromCache(requestId, tenantId);
        if (session == null) {
            return null;
        }
        // Return NOT_FOUND to avoid cross-tenant attacks.
        if (tenantId != session.getTenantId()) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_REQUEST_NOT_FOUND);
        }
        VPSessionStatus status = session.getStatus();
        // Block callers from consuming the result endpoint while verification is still in progress.
        if (status == VPSessionStatus.ACTIVE) {
            throw PresentationCoreExceptionHandler.handleClientException(
                    PresentationCoreErrorCode.VP_SESSION_PENDING);
        }
        // Populate the response DTO with all fields the caller needs to determine the outcome.
        VPVerificationResultDTO verificationSessionResponse = new VPVerificationResultDTO();
        verificationSessionResponse.setStatus(status);
        verificationSessionResponse.setVerificationResponse(session.getVerificationResponse());
        verificationSessionResponse.setErrorType(session.getErrorType());
        verificationSessionResponse.setErrorDescription(session.getErrorDescription());

        return verificationSessionResponse;
    }
}
