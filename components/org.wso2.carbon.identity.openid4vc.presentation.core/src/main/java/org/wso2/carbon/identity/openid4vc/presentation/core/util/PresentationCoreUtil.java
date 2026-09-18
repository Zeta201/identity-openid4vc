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

package org.wso2.carbon.identity.openid4vc.presentation.core.util;

import com.nimbusds.jose.jwk.ECKey;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.PresentationCoreConstants;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for VP server related operations.
 */
public class PresentationCoreUtil {

    private static final Log LOG = LogFactory.getLog(PresentationCoreUtil.class);

    // X.509 SAN GeneralName type for dNSName (RFC 5280).
    private static final int SAN_TYPE_DNS = 2;

    private PresentationCoreUtil() {

    }

    /**
     * Resolve base URL from framework utilities.
     */
    public static String buildServerBaseUrl() throws PresentationCoreServerException {

        try {
            return ServiceURLBuilder.create()
                    .build(IdentityUtil.getHostName())
                    .getAbsolutePublicUrlWithoutPath();
        } catch (URLBuilderException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.BASE_URL_RESOLUTION_ERROR, e);
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
    public static String buildClientId(String scheme, String tenantDomain)
            throws PresentationCoreException {

        if (Constants.DEFAULT_CLIENT_ID_SCHEME.equals(scheme)) {
            return Constants.DEFAULT_CLIENT_ID_SCHEME + ":" + resolveServerSanDns(tenantDomain);
        } else if (Constants.CLIENT_ID_SCHEME_X509_HASH.equals(scheme)) {
            return Constants.CLIENT_ID_SCHEME_X509_HASH + ":" + resolveServerCertHash(tenantDomain);
        } else {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.UNSUPPORTED_CLIENT_ID_SCHEME, null, scheme);
        }
    }

    /**
     * Compute the base64url SHA-256 hash of the tenant's signing certificate.
     */
    public static String resolveServerCertHash(String tenantDomain) throws PresentationCoreServerException {

        try {
            return computeCertHash(loadTenantSigningCertificate(tenantDomain));
        } catch (IdentityKeyStoreResolverException | KeyStoreException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_CERTIFICATE_ERROR, e);
        }
    }

    /**
     * Compute base64url(SHA-256(DER(cert))).
     */
    public static String computeCertHash(X509Certificate cert) throws PresentationCoreServerException {

        try {
            byte[] derEncoded = cert.getEncoded();
            byte[] hash = MessageDigest.getInstance(Constants.Algorithms.SHA_256).digest(derEncoded);
            return Base64URL.encode(hash).toString();
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_CERTIFICATE_ERROR, e);
        }
    }

    /**
     * Load the tenant signing certificate and extract the first dNSName SAN entry.
     */
    public static String resolveServerSanDns(String tenantDomain) throws PresentationCoreException {

        try {
            String sanDns = extractSanDns(loadTenantSigningCertificate(tenantDomain));
            if (StringUtils.isBlank(sanDns)) {
                throw PresentationCoreExceptionHandler.handleServerException(
                        PresentationCoreErrorCode.SIGNING_CERTIFICATE_ERROR, null);
            }
            return sanDns;
        } catch (Exception e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_CERTIFICATE_ERROR, e);
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
                    if (san.size() >= 2 && Integer.valueOf(SAN_TYPE_DNS).equals(san.get(0))) {
                        return (String) san.get(1);
                    }
                }
            }
        } catch (CertificateParsingException e) {
            LOG.warn("Failed to parse SAN extensions from certificate.", e);
        }
        return null;
    }

    public static String extractFirstFormParam(Map<String, List<String>> params, String key) {

        List<String> values = params.get(key);
        return (values != null && !values.isEmpty()) ? values.getFirst() : null;
    }

    public static Map<String, String> flattenVpTokenMap(Map<String, Object> rawMap) {

        Map<String, String> flattenedMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : rawMap.entrySet()) {
            Object val = entry.getValue();
            if (val instanceof List) {
                List<?> list = (List<?>) val;
                flattenedMap.put(entry.getKey(), list.isEmpty() ? null : String.valueOf(list.getFirst()));
            } else {
                flattenedMap.put(entry.getKey(), val != null ? String.valueOf(val) : null);
            }
        }
        return flattenedMap;
    }

    public static ECPrivateKey loadEcPrivateKey(KeyStore ks, String keyAlias, char[] keyPassword)
            throws GeneralSecurityException, PresentationCoreException {

        PrivateKey key = (PrivateKey) ks.getKey(keyAlias, keyPassword);
        if (!(key instanceof ECPrivateKey)) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_KEY_ERROR, null);
        }
        return (ECPrivateKey) key;
    }

    public static List<Base64> buildX5cChain(Certificate[] certChain, X509Certificate cert)
            throws GeneralSecurityException {

        List<Base64> chain = new ArrayList<>();
        if (certChain != null && certChain.length > 1) {
            for (Certificate c : certChain) {
                chain.add(Base64.encode(c.getEncoded()));
            }
        } else {
            chain.add(Base64.encode(cert.getEncoded()));
        }
        return chain;
    }

    public static char[] resolveKeyPassword(KeyStoreManager ksm, String tenantDomain)
            throws PresentationCoreException {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            String pwd = ServerConfiguration.getInstance().getFirstProperty(
                    RegistryResources.SecurityManagement.SERVER_PRIVATE_KEY_PASSWORD);
            return pwd != null ? pwd.toCharArray() : new char[0];
        }
        try {
            char[] pwd = ksm.getPrivateKeyPassword(tenantDomain.replace(".", "-") + ".jks");
            return pwd != null ? pwd : new char[0];
        } catch (CarbonException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_KEY_ERROR, e);
        }
    }

    public static ECKey resolveEphemeralPublicKey(VPSession session) throws PresentationCoreServerException {

        if (StringUtils.isBlank(session.getEphemeralPrivateKeyJwk())) {
            return null;
        }
        try {
            return ECKey.parse(session.getEphemeralPrivateKeyJwk()).toPublicJWK();
        } catch (ParseException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.EPHEMERAL_KEY_ERROR, e);
        }
    }

    /**
     * Builds the tenant-scoped {@code request_uri} at which the wallet fetches the signed
     * authorization request JWT.
     *
     * @param tenantDomain the tenant domain to scope the URL to
     * @param requestId    the VP session ID used as the final path segment
     * @return the absolute public URL string
     * @throws PresentationCoreServerException if the base URL cannot be resolved
     */
    public static String buildRequestUri(String tenantDomain, String requestId)
            throws PresentationCoreServerException {

        try {
            // Build the URL under the OID4VP requests context path and append the request ID.
            return buildServiceUrl(tenantDomain,
                    PresentationCoreConstants.CONTEXT_OID4VP_REQUESTS, requestId)
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.BASE_URL_RESOLUTION_ERROR, e);
        }
    }

    /**
     * Builds the tenant-scoped {@code response_uri} where the wallet POST the VP token.
     *
     * @param tenantDomain the tenant domain to scope the URL to
     * @return the absolute public URL string
     * @throws PresentationCoreServerException if the base URL cannot be resolved
     */
    public static String buildResponseUri(String tenantDomain) throws PresentationCoreServerException {

        try {
            // Build the URL under the OID4VP responses context path.
            return buildServiceUrl(tenantDomain, PresentationCoreConstants.CONTEXT_OID4VP_RESPONSES)
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.BASE_URL_RESOLUTION_ERROR, e);
        }
    }

    /**
     * Constructs a {@link ServiceURL} for the given tenant and path segments.
     *
     * <p>Omits the tenant qualifier for the super-tenant so the URL does not include
     * an unnecessary {@code /t/carbon.super} segment.
     *
     * @param tenantDomain the tenant domain; super-tenant is left unqualified
     * @param pathSegments one or more path segments appended after the context root
     * @return the built {@link ServiceURL}
     * @throws URLBuilderException if the URL cannot be assembled
     */
    public static ServiceURL buildServiceUrl(String tenantDomain, String... pathSegments) throws URLBuilderException {

        // Append all path segments to the builder.
        ServiceURLBuilder builder = ServiceURLBuilder.create().addPath(pathSegments);
        // Qualify the URL with the tenant only for non-super tenants.
        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            builder.setTenant(tenantDomain);
        }
        return builder.build();
    }

    /**
     * Builds the wallet deep-link URL used to invoke the wallet application.
     *
     * <p>Produces {@code openid4vp://?client_id=<encoded>&request_uri=<encoded>}.
     *
     * @param clientId   the {@code client_id} to embed in the URL
     * @param requestUri the {@code request_uri} the wallet will fetch for the signed request object
     * @return the percent-encoded wallet deep-link URL string
     */
    public static String buildWalletUrl(String clientId, String requestUri) {

        // Encode both parameters to ensure reserved characters do not break URL parsing.
        return Constants.Protocol.OPENID4VP_SCHEME + "?"
                + Constants.RequestParams.CLIENT_ID + "=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&" + Constants.RequestParams.REQUEST_URI + "="
                + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
    }
}
