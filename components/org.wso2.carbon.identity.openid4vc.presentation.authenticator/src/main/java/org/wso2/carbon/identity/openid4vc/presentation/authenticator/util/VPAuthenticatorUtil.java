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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.internal.VPDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowStatus;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.VPConfigService;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Utility class for VP server related operations.
 */
public class VPAuthenticatorUtil {

    private static final Log LOG = LogFactory.getLog(VPAuthenticatorUtil.class);

    private VPAuthenticatorUtil() { }

    /**
     * Resolve base URL from framework utilities.
     */
    public static String resolveBaseUrl() throws VPAuthenticatorException {

        try {
            return ServiceURLBuilder.create()
                    .build(IdentityUtil.getHostName())
                    .getAbsolutePublicUrlWithoutPath();
        } catch (URLBuilderException e) {
            throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Error while resolving base URL.", e);
        }
    }

    /**
     * Load the full tenant config in one registry read. Returns an empty config on failure.
     */
    public static VPConfigService.TenantConfig loadTenantConfig(String tenantDomain) {

        try {
            VPConfigService configService = VPDataHolder.getVPConfigService();
            if (configService == null || StringUtils.isBlank(tenantDomain)) {
                return new VPConfigService.TenantConfig();
            }
            return configService.getConfig(tenantDomain);
        } catch (Exception e) {
            LOG.warn("Failed to read tenant config for "
                    + tenantDomain.replace("\r", "").replace("\n", "") + "; using server defaults.", e);
            return new VPConfigService.TenantConfig();
        }
    }

    /**
     * Resolve signing key alias for a specific tenant.
     */
    public static String resolveSigningKeyAlias(String tenantDomain) {

        try {
            return KeyStoreUtil.getTenantECKeyAlias(tenantDomain);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to resolve ECDSA key alias for tenant: " + tenantDomain, e);
        }
    }

    /**
     * Resolve the client_id value based on the configured scheme.
     */
    public static String resolveClientIdForScheme(String scheme, String baseUrl, String tenantDomain)
            throws VPAuthenticatorException {

        if (VPConstants.DEFAULT_CLIENT_ID_SCHEME.equals(scheme)) {
            return VPConstants.DEFAULT_CLIENT_ID_SCHEME + ":" + resolveServerSanDns(tenantDomain);
        } else if (Constants.CLIENT_ID_SCHEME_X509_HASH.equals(scheme)) {
            return Constants.CLIENT_ID_SCHEME_X509_HASH + ":" + resolveServerCertHash(tenantDomain);
        } else {
            throw new VPAuthenticatorException(
                    VPAuthenticatorErrorCode.INVALID_REQUEST,
                    "Unsupported client_id_scheme: " + scheme);
        }
    }

    /**
     * Compute the base64url SHA-256 hash of the tenant's signing certificate.
     */
    public static String resolveServerCertHash(String tenantDomain) throws VPAuthenticatorException {

        try {
            return computeCertHash(loadTenantSigningCertificate(tenantDomain));
        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (Exception e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to compute cert hash for x509_hash scheme.", e);
        }
    }

    /**
     * Compute base64url(SHA-256(DER(cert))).
     */
    public static String computeCertHash(X509Certificate cert) throws VPAuthenticatorException {

        try {
            byte[] derEncoded = cert.getEncoded();
            byte[] hash = MessageDigest.getInstance(VPConstants.Algorithms.SHA_256).digest(derEncoded);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to compute SHA-256 hash of certificate.", e);
        }
    }

    /**
     * Load the tenant signing certificate and extract the first dNSName SAN entry.
     */
    public static String resolveServerSanDns(String tenantDomain) throws VPAuthenticatorException {

        try {
            String sanDns = extractSanDns(loadTenantSigningCertificate(tenantDomain));
            if (StringUtils.isBlank(sanDns)) {
                throw new VPAuthenticatorServerException(
                        VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "No dNSName SAN entry found in server certificate. "
                                + "x509_san_dns scheme requires the TLS certificate to have a SAN dNSName.");
            }
            return sanDns;
        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (Exception e) {
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to load server certificate for x509_san_dns scheme.", e);
        }
    }

    /**
     * Loads the end-entity signing certificate for the given tenant.
     * Prefers the first entry in the certificate chain (end-entity cert); falls back to
     * the single-cert alias lookup for keystores that don't store a chain.
     */
    private static X509Certificate loadTenantSigningCertificate(String tenantDomain)
            throws IdentityKeyStoreResolverException, KeyStoreException {

        KeyStore ks = IdentityKeyStoreResolver.getInstance().getKeyStore(tenantDomain, InboundProtocol.OAUTH);
        String alias = resolveSigningKeyAlias(tenantDomain);
        Certificate[] chain = ks.getCertificateChain(alias);
        return (X509Certificate) (chain != null && chain.length > 0
                ? chain[0] : ks.getCertificate(alias));
    }

    /**
     * Extract the first dNSName Subject Alternative Name entry from an X.509 certificate.
     */
    public static String extractSanDns(X509Certificate cert) {

        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        return (String) san.get(1);
                    }
                }
            }
        } catch (CertificateParsingException e) {
            LOG.warn("Failed to parse SAN extensions from certificate.", e);
        }
        return null;
    }

    /**
     * Resolves the subject identifier from verified credential claims.
     * Resolves the subject identifier for the authenticated user from the verified credential claims.
     * The raw claim value is namespaced by the credential issuer (the JWT {@code iss} value from
     * {@code metadata}) to prevent cross-issuer collisions: two credentials from different issuers
     * that happen to carry the same claim value (e.g. the same email address) will resolve to
     * different IS identities.
     * <p>
     * Format: {@code <issuer>#<claimValue>}, e.g.
     * {@code https://issuer.example.com/oid4vci#alice@example.com}.
     * Falls back to the raw claim value when no issuer is available in metadata.
     *
     * @param verifiedClaims   claims extracted from the verified credential.
     * @param subjectClaimName remote claim URI configured as the subject attribute; may be null.
     * @param metadata         presentation metadata carrying the issuer identifier; may be null.
     * @return namespaced subject identifier string, or null if not resolvable.
     */
    public static String resolveSubjectIdentifier(Map<String, Object> verifiedClaims,
                                                   String subjectClaimName,
                                                   PresentationMetadata metadata) {

        // 1. Configured subject attribute claim.
        if (StringUtils.isNotBlank(subjectClaimName)) {
            Object val = verifiedClaims.get(subjectClaimName);
            if (val != null && StringUtils.isNotBlank(val.toString())) {
                return namespace(val.toString(), metadata);
            }
            LOG.warn("Configured subject attribute '" + subjectClaimName
                    + "' was not found in the verified credential claims; falling back to cnf.");
        }

        // 2. cnf (holder-binding) claim — the VC equivalent of OIDC's sub.
        String cnfIdentifier = resolveSubjectFromCnf(verifiedClaims);
        if (cnfIdentifier != null) {
            return namespace(cnfIdentifier, metadata);
        }

        return null;
    }

    /**
     * Extracts a stable string identifier from the {@code cnf} (confirmation) claim.
     * Tries, in order: {@code cnf.kid}, {@code cnf.jkt}, {@code cnf.jwk.kid}.
     * Returns {@code null} if no usable identifier is found.
     */
    private static String resolveSubjectFromCnf(Map<String, Object> verifiedClaims) {

        Object cnfRaw = verifiedClaims.get(VPConstants.JWTClaims.CNF);
        if (cnfRaw == null) {
            return null;
        }
        if (cnfRaw instanceof Map) {
            Map<?, ?> cnf = (Map<?, ?>) cnfRaw;

            // cnf.kid
            String kid = stringValue(cnf.get(VPConstants.JWTClaims.KID));
            if (kid != null) return kid;

            // cnf.jkt (JWK thumbprint)
            String jkt = stringValue(cnf.get(VPConstants.JWTClaims.JKT));
            if (jkt != null) return jkt;

            // cnf.jwk.kid
            Object jwkRaw = cnf.get(VPConstants.JWTClaims.JWK);
            if (jwkRaw instanceof Map) {
                String jwkKid = stringValue(((Map<?, ?>) jwkRaw).get(VPConstants.JWTClaims.KID));
                if (jwkKid != null) return jwkKid;
            }
        } else {
            // cnf as a plain string (e.g. a DID)
            String plain = stringValue(cnfRaw);
            if (plain != null) return plain;
        }
        return null;
    }

    private static String namespace(String value, PresentationMetadata metadata) {

        if (metadata != null && StringUtils.isNotBlank(metadata.getIssuer())) {
            return metadata.getIssuer() + "#" + value;
        }
        return value;
    }

    private static String stringValue(Object obj) {

        if (obj == null) return null;
        String s = obj.toString().trim();
        return s.isEmpty() ? null : s;
    }

    /**
     * Returns the remote VP claim name configured as the Subject Attribute on the IdP's Attributes tab.
     * This claim's value in the verified credential will become the subject identifier for the
     * authenticated user.
     *
     * @param externalIdPConfig the external IdP configuration; may be null.
     * @return configured subject claim URI, or null if none is set.
     */
    public static String resolveSubjectClaimName(ExternalIdPConfig externalIdPConfig) {

        if (externalIdPConfig == null
                || externalIdPConfig.getIdentityProvider() == null
                || externalIdPConfig.getIdentityProvider().getClaimConfig() == null) {
            return null;
        }
        return externalIdPConfig.getIdentityProvider().getClaimConfig().getUserClaimURI();
    }

    /**
     * Resolves the VP flow timeout in milliseconds from the given authenticator properties map.
     * Returns the configured default when the property is absent, blank, non-numeric, or not positive.
     *
     * @param props the authenticator or executor properties map; may be null
     * @return the timeout in milliseconds derived from the property, or the default if the value is absent or invalid
     */
    public static long resolveTimeoutMs(Map<String, String> props) {

        String timeoutStr = props != null ? props.get(Constants.PROP_TIMEOUT_SECONDS) : null;
        if (StringUtils.isNotBlank(timeoutStr)) {
            try {
                int seconds = Integer.parseInt(timeoutStr.trim());
                if (seconds > 0) {
                    return seconds * 1000L;
                }
            } catch (NumberFormatException e) {
                LOG.warn("Invalid timeout value '"
                        + timeoutStr.replace("\r", "").replace("\n", "") + "'; using default.");
            }
        }

        return Long.parseLong(Constants.PROP_TIMEOUT_DEFAULT_VALUE) * 1000L;
    }

    /**
     * Marks a VP session as FAILED if it exists and has not already reached a terminal state.
     * Best-effort: swallows any cache/store exceptions so it never masks the original error.
     * All servlet and executor catch blocks must call this so the browser polling loop stops
     * immediately instead of waiting for session expiry.
     *
     * @param requestId the VP session identifier; does nothing when blank or null
     * @param reason    human-readable failure reason surfaced to the browser via the status endpoint
     */
    public static void markSessionFailed(String requestId, String reason) {

        if (StringUtils.isBlank(requestId)) {
            return;
        }
        try {
            VPFlowSession session = VPSessionCache.getInstance().get(requestId);
            if (session == null) {
                return;
            }
            VPFlowStatus current = session.getStatus();
            if (current == VPFlowStatus.VERIFIED || current == VPFlowStatus.FAILED) {
                return;
            }
            session.setStatus(VPFlowStatus.FAILED);
            session.setFailureReason(reason);
            VPSessionCache.getInstance().put(requestId, session);
        } catch (Exception e) {
            LOG.warn("Failed to mark VP session as FAILED for requestId: "
                    + requestId.replace("\r", "").replace("\n", ""), e);
        }
    }

}
