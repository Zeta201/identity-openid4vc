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
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.constant.PresentationCoreConstants;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;
import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreServerException;
import org.wso2.carbon.identity.openid4vc.presentation.core.model.VPSession;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
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
     * Resolves the ECDSA signing key alias for the given tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return Key alias.
     * @throws IllegalStateException If the alias cannot be resolved.
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
     * Builds the client ID value for the given scheme and tenant.
     *
     * @param scheme       Client ID scheme.
     * @param tenantDomain Tenant domain.
     * @return Client ID.
     * @throws PresentationCoreException If the certificate cannot be loaded or the scheme is unsupported.
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
     * Computes the base64url-encoded SHA-256 hash of the tenant's signing certificate.
     *
     * @param tenantDomain Tenant domain.
     * @return Base64url SHA-256 hash.
     * @throws PresentationCoreServerException If the certificate cannot be loaded or hashed.
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
     * Computes the base64url-encoded SHA-256 hash of the given X.509 certificate.
     *
     * @param cert Certificate to hash.
     * @return Base64url SHA-256 hash.
     * @throws PresentationCoreServerException If DER encoding or hashing fails.
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
     * Resolves the first dNSName Subject Alternative Name entry of the tenant's signing certificate.
     *
     * @param tenantDomain Tenant domain.
     * @return First dNSName SAN value.
     * @throws PresentationCoreException If the certificate has no dNSName SAN or cannot be loaded.
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
     * @param tenantDomain Tenant domain.
     * @return End-entity X.509 signing certificate.
     * @throws IdentityKeyStoreResolverException If the keystore cannot be accessed.
     * @throws KeyStoreException                 If the alias lookup fails.
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
     * @param cert Certificate to inspect.
     * @return First dNSName SAN value, or null if none is present or parsing fails.
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
     * @param params Form parameter map from the wallet's HTTP POST.
     * @param key    Parameter name to look up.
     * @return First value, or null if the key is absent or the list is empty.
     */
    public static String extractFirstFormParam(Map<String, List<String>> params, String key) {

        List<String> values = params.get(key);
        return (values != null && !values.isEmpty()) ? values.getFirst() : null;
    }

    /**
     * Flattens a VP token map from the wallet's JSON response into a map of plain string values.
     *
     * @param rawMap Raw vp_token map parsed from the wallet's claims.
     * @return Flattened map with one string value per credential identifier key.
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
     * Loads the EC private key for the given alias from the keystore.
     *
     * @param ks          Keystore to query.
     * @param keyAlias    Alias of the private key entry.
     * @param keyPassword Password protecting the key entry.
     * @return EC private key.
     * @throws GeneralSecurityException  If the key entry cannot be accessed.
     * @throws PresentationCoreException If the resolved key is not an EC private key.
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
     * Builds the x5c certificate chain list for inclusion in a JWS header.
     *
     * @param certChain Full certificate chain from the keystore; may be null.
     * @param cert      End-entity certificate to use as a fallback.
     * @return Base64-encoded certificate list in x5c order.
     * @throws GeneralSecurityException If any certificate cannot be DER-encoded.
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
     * @param ksm          Keystore manager instance.
     * @param tenantDomain Tenant domain.
     * @return Key password; empty array if no password is configured.
     * @throws PresentationCoreException If the tenant keystore password cannot be retrieved.
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
     * Extracts the ephemeral EC public key stored on a VP session.
     *
     * @param session VP session that may carry an ephemeral private key JWK.
     * @return Public JWK derived from the session's ephemeral private key, or null if none is stored.
     * @throws PresentationCoreServerException If the stored JWK cannot be parsed.
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
     * @param ks       Keystore to query.
     * @param keyAlias Alias of the signing key.
     * @return End-entity X.509 signing certificate.
     * @throws KeyStoreException               If the alias lookup fails.
     * @throws PresentationCoreServerException If no certificate is found for the alias.
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
     * Builds the tenant-scoped request_uri at which the wallet fetches the signed authorization request JWT.
     *
     * @param tenantDomain Tenant domain to scope the URL to.
     * @param requestId    VP session ID used as the final path segment.
     * @return Absolute public URL.
     * @throws PresentationCoreServerException If the base URL cannot be resolved.
     */
    public static String buildRequestUri(String tenantDomain, String requestId)
            throws PresentationCoreServerException {

        try {
            return buildServiceUrl(tenantDomain,
                    PresentationCoreConstants.CONTEXT_OID4VP_REQUESTS, requestId)
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.BASE_URL_RESOLUTION_ERROR, e);
        }
    }

    /**
     * Builds the tenant-scoped response_uri where the wallet posts the VP token.
     *
     * @param tenantDomain Tenant domain to scope the URL to.
     * @return Absolute public URL.
     * @throws PresentationCoreServerException If the base URL cannot be resolved.
     */
    public static String buildResponseUri(String tenantDomain) throws PresentationCoreServerException {

        try {
            return buildServiceUrl(tenantDomain, PresentationCoreConstants.CONTEXT_OID4VP_RESPONSES)
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw PresentationCoreExceptionHandler.handleServerException(
                    PresentationCoreErrorCode.BASE_URL_RESOLUTION_ERROR, e);
        }
    }

    /**
     * Constructs a service URL for the given tenant and path segments.
     *
     * @param tenantDomain Tenant domain; super-tenant is left unqualified.
     * @param pathSegments One or more path segments appended after the context root.
     * @return Built service URL.
     * @throws URLBuilderException If the URL cannot be assembled.
     */
    public static ServiceURL buildServiceUrl(String tenantDomain, String... pathSegments) throws URLBuilderException {

        ServiceURLBuilder builder = ServiceURLBuilder.create().addPath(pathSegments);
        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            builder.setTenant(tenantDomain);
        }
        return builder.build();
    }

    /**
     * Builds the wallet deep-link URL used to invoke the wallet application.
     *
     * @param clientId   Client ID to embed in the URL.
     * @param requestUri Request URI the wallet will fetch for the signed request object.
     * @return Percent-encoded wallet deep-link URL.
     */
    public static String buildWalletUrl(String clientId, String requestUri) {

        return Constants.Protocol.OPENID4VP_SCHEME + "?"
                + Constants.RequestParams.CLIENT_ID + "=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&" + Constants.RequestParams.REQUEST_URI + "="
                + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
    }

    /**
     * Decrypts a direct_post.jwt JWE and extracts the inner JWT claims.
     *
     * @param jweObject              Parsed JWE object received from the wallet.
     * @param ephemeralPrivateKeyJwk Ephemeral EC private key JWK stored on the session.
     * @return Decrypted JWT claims set.
     * @throws ParseException If the ephemeral key or inner JWT cannot be parsed.
     * @throws JOSEException  If ECDH-ES decryption fails.
     */
    public static JWTClaimsSet decryptJweResponse(JWEObject jweObject, String ephemeralPrivateKeyJwk)
            throws ParseException, JOSEException {

        // Decrypt the JWE using the session's ephemeral EC private key.
        jweObject.decrypt(new ECDHDecrypter(ECKey.parse(ephemeralPrivateKeyJwk)));
        SignedJWT innerJwt = jweObject.getPayload().toSignedJWT();
        return innerJwt != null
                ? innerJwt.getJWTClaimsSet()
                : JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());
    }

}
