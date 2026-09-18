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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

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
     * Resolves the ECDSA signing key alias for the given tenant from the keystore manager.
     *
     * @param tenantDomain the tenant domain whose key alias to resolve
     * @return the key alias string
     * @throws IllegalStateException if the alias cannot be resolved
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
     * Builds the {@code client_id} value for the given scheme and tenant.
     *
     * <p>Supports {@code x509_san_dns} (prefixed with the first dNSName SAN of the signing cert)
     * and {@code x509_hash} (prefixed with the base64url SHA-256 of the signing cert). Throws for
     * any unrecognized scheme.
     *
     * @param scheme       the {@code client_id_scheme} configured for the tenant
     * @param tenantDomain the tenant domain used to load the signing certificate
     * @return the fully constructed {@code client_id} string
     * @throws PresentationCoreException if the certificate cannot be loaded or the scheme is unsupported
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
     * Computes and returns the base64url-encoded SHA-256 hash of the tenant's signing certificate.
     *
     * @param tenantDomain the tenant domain whose signing certificate to hash
     * @return the base64url SHA-256 hash string
     * @throws PresentationCoreServerException if the certificate cannot be loaded or hashed
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
     * Computes {@code base64url(SHA-256(DER(cert)))} for the given X.509 certificate.
     *
     * @param cert the certificate to hash
     * @return the base64url-encoded SHA-256 hash string
     * @throws PresentationCoreServerException if DER encoding or hashing fails
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
     * Loads the tenant's signing certificate and returns the first dNSName Subject Alternative
     * Name entry, which is used as the {@code x509_san_dns} client ID value.
     *
     * @param tenantDomain the tenant domain whose certificate to inspect
     * @return the first dNSName SAN value
     * @throws PresentationCoreException if the certificate has no dNSName SAN or cannot be loaded
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
     * Loads the end-entity signing certificate for the given tenant from the OAUTH keystore.
     *
     * <p>Prefers the first entry in the certificate chain (end-entity cert); falls back to a
     * direct alias lookup for keystores that do not store a full chain.
     *
     * @param tenantDomain the tenant domain whose keystore to query
     * @return the end-entity X.509 signing certificate
     * @throws IdentityKeyStoreResolverException if the keystore cannot be accessed
     * @throws KeyStoreException                 if the alias lookup fails
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
     * Extracts the first dNSName Subject Alternative Name entry from an X.509 certificate.
     *
     * @param cert the certificate to inspect
     * @return the first dNSName SAN value, or {@code null} if none is present or parsing fails
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

    /**
     * Returns the first value for the given key from a multi-valued form parameter map.
     *
     * @param params the form parameter map from the wallet's HTTP POST
     * @param key    the parameter name to look up
     * @return the first value, or {@code null} if the key is absent or the list is empty
     */
    public static String extractFirstFormParam(Map<String, List<String>> params, String key) {

        List<String> values = params.get(key);
        return (values != null && !values.isEmpty()) ? values.getFirst() : null;
    }

    /**
     * Flattens a VP token map from the wallet's JSON response into a {@code Map<String, String>}.
     *
     * <p>Each value is converted to a plain string. When the raw value is a JSON array, only the
     * first element is kept; when it is {@code null}, the mapped value is {@code null}.
     *
     * @param rawMap the raw {@code vp_token} map parsed from the wallet's claims
     * @return a flattened map with one string value per credential identifier key
     */
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

    /**
     * Loads and returns the EC private key for the given alias from the keystore.
     *
     * @param ks          the keystore to query
     * @param keyAlias    the alias of the private key entry
     * @param keyPassword the password protecting the key entry
     * @return the EC private key
     * @throws GeneralSecurityException  if the key entry cannot be accessed
     * @throws PresentationCoreException if the resolved key is not an EC private key
     */
    public static ECPrivateKey loadEcPrivateKey(KeyStore ks, String keyAlias, char[] keyPassword)
            throws GeneralSecurityException, PresentationCoreException {

        PrivateKey key = (PrivateKey) ks.getKey(keyAlias, keyPassword);
        if (!(key instanceof ECPrivateKey)) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_KEY_ERROR, null);
        }
        return (ECPrivateKey) key;
    }

    /**
     * Builds the {@code x5c} certificate chain list for inclusion in a JWS header.
     *
     * <p>When the keystore contains a multi-certificate chain, all entries are encoded.
     * When only a single certificate is available (no chain stored), that certificate alone
     * is used.
     *
     * @param certChain the full certificate chain from the keystore; may be {@code null}
     * @param cert      the end-entity certificate to use as a fallback
     * @return the base64-encoded certificate list in {@code x5c} order
     * @throws GeneralSecurityException if any certificate cannot be DER-encoded
     */
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

    /**
     * Resolves the private key password for the given tenant's keystore entry.
     *
     * <p>For the super-tenant, reads the password from the server configuration. For other
     * tenants, derives the JKS filename from the tenant domain and asks the keystore manager.
     *
     * @param ksm          the keystore manager instance
     * @param tenantDomain the tenant domain whose key password to resolve
     * @return the key password as a char array; empty array if no password is configured
     * @throws PresentationCoreException if the tenant keystore password cannot be retrieved
     */
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

    /**
     * Extracts and returns the ephemeral EC public key stored on a VP session.
     *
     * <p>Returns {@code null} when the session has no ephemeral key, which indicates that
     * the response mode does not require encryption.
     *
     * @param session the VP session that may carry an ephemeral private key JWK
     * @return the public JWK derived from the session's ephemeral private key, or {@code null}
     * @throws PresentationCoreServerException if the stored JWK cannot be parsed
     */
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
     * Resolves the signing certificate from the given keystore by alias.
     *
     * <p>Prefers the first entry in the certificate chain (end-entity cert); falls back to a
     * direct alias lookup for keystores that do not store a full chain.
     *
     * @param ks       the keystore to query
     * @param keyAlias the alias of the signing key
     * @return the end-entity X.509 signing certificate
     * @throws KeyStoreException               if the alias lookup fails
     * @throws PresentationCoreServerException if no certificate is found for the alias
     */
    public static X509Certificate resolveSigningCertificate(KeyStore ks, String keyAlias)
            throws KeyStoreException, PresentationCoreServerException {

        // Prefer chain[0] (end-entity); fall back to a direct alias lookup.
        Certificate[] chain = ks.getCertificateChain(keyAlias);
        X509Certificate cert = (X509Certificate) (chain != null && chain.length > 0
                ? chain[0] : ks.getCertificate(keyAlias));
        if (cert == null) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.SIGNING_CERTIFICATE_ERROR, null);
        }
        return cert;
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

    /**
     * Decrypts a {@code direct_post.jwt} JWE and extracts the inner JWT claims.
     *
     * <p>The JWE is decrypted with the session's ephemeral EC private key using ECDH-ES. The
     * decrypted payload is treated as a signed JWT when possible; otherwise plain JSON claim
     * parsing is used as a fallback.
     *
     * @param jweObject              the parsed JWE object received from the wallet
     * @param ephemeralPrivateKeyJwk the ephemeral EC private key JWK stored on the session
     * @return the decrypted {@link JWTClaimsSet}
     * @throws ParseException if the ephemeral key or inner JWT cannot be parsed
     * @throws JOSEException  if ECDH-ES decryption fails
     */
    public static JWTClaimsSet decryptJweResponse(JWEObject jweObject, String ephemeralPrivateKeyJwk)
            throws ParseException, JOSEException {

        // Decrypt the JWE using the session's ephemeral EC private key.
        jweObject.decrypt(new ECDHDecrypter(ECKey.parse(ephemeralPrivateKeyJwk)));
        // Prefer the inner signed JWT; fall back to plain JSON if the payload is unsigned.
        SignedJWT innerJwt = jweObject.getPayload().toSignedJWT();
        return innerJwt != null
                ? innerJwt.getJWTClaimsSet()
                : JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());
    }

}
