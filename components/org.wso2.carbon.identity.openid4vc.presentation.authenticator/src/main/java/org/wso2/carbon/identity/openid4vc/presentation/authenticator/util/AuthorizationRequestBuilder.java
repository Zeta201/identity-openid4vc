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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.util;

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
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants.InboundProtocol;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPAuthorizationRequest;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants.VC_SD_JWT_FORMAT;

/**
 * Builds and signs the OpenID4VP authorization request JWT.
 *
 * <p>Owns all X.509/keystore machinery and JWT construction so that
 * {@link org.wso2.carbon.identity.openid4vc.presentation.authenticator.service.impl.VPFlowServiceImpl}
 * can remain focused on session lifecycle.
 */
public class AuthorizationRequestBuilder {

    private static final Log LOG = LogFactory.getLog(AuthorizationRequestBuilder.class);

    private AuthorizationRequestBuilder() {

    }

    /**
     * Signs the OpenID4VP authorization request object and returns a compact JWT.
     *
     * <p>Loads the tenant's EC signing key, builds a JWS header with the x5c certificate chain,
     * assembles all required protocol claims (DCQL query, client metadata), and signs with ECDSA.
     *
     * @param vpRequest          Assembled authorization request data.
     * @param dcqlQuery          DCQL credential query to embed in the JWT.
     * @param tenantDomain       Tenant domain used to load the signing key.
     * @param tenantId           Numeric tenant ID for {@link KeyStoreManager} lookup.
     * @param ephemeralPublicKey Ephemeral EC key embedded in {@code client_metadata.jwks}
     *                           for {@code direct_post.jwt} encrypted responses;
     *                           {@code null} for plain {@code direct_post}.
     * @param clientIdScheme     Resolved client ID scheme.
     * @return Compact serialized signed JWT.
     * @throws VPAuthenticatorException On key access, signing, or serialization failure.
     */
    public static String sign(VPAuthorizationRequest vpRequest,
                              DcqlQuery dcqlQuery,
                              String tenantDomain,
                              int tenantId,
                              ECKey ephemeralPublicKey,
                              String clientIdScheme) throws VPAuthenticatorException {

        try {
            String scheme = StringUtils.defaultIfBlank(clientIdScheme, VPConstants.DEFAULT_CLIENT_ID_SCHEME);
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
            if (cert == null) {
                throw new VPAuthenticatorServerException(VPAuthenticatorErrorCode.INTERNAL_SERVER_ERROR,
                        "No certificate found in tenant keystore for alias '" + keyAlias + "'.");
            }

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

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .audience(VPConstants.Protocol.REQUEST_AUDIENCE)
                    .claim(VPConstants.RequestParams.CLIENT_ID, clientId)
                    .claim(VPConstants.JWTClaims.CLIENT_ID_SCHEME, scheme)
                    .claim(VPConstants.RequestParams.RESPONSE_TYPE,
                            VPConstants.Protocol.RESPONSE_TYPE_VP_TOKEN)
                    .claim(VPConstants.RequestParams.RESPONSE_MODE, vpRequest.getResponseMode())
                    .claim(VPConstants.RequestParams.RESPONSE_URI, vpRequest.getResponseUri())
                    .claim(VPConstants.RequestParams.NONCE, vpRequest.getNonce())
                    .claim(VPConstants.RequestParams.STATE, vpRequest.getRequestId())
                    .issueTime(new Date())
                    .expirationTime(new Date(vpRequest.getExpiresAt()))
                    .jwtID(UUID.randomUUID().toString())
                    .claim(VPConstants.JWTClaims.DCQL_QUERY, DcqlQuerySerializer.toMap(dcqlQuery))
                    .claim(Constants.CLAIM_CLIENT_METADATA, buildClientMetadata(clientId, ephemeralPublicKey))
                    .build();

            JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(claims.toJSONObject()));
            jwsObject.sign(jwsSigner);
            return jwsObject.serialize();

        } catch (VPAuthenticatorException e) {
            throw e;
        } catch (GeneralSecurityException | JOSEException | IdentityKeyStoreResolverException e) {
            LOG.error("Error building request object JWT for tenant=" + tenantDomain, e);
            throw new VPAuthenticatorServerException(
                    VPAuthenticatorErrorCode.SIGNING_ERROR,
                    "Error building request object JWT.", e);
        }
    }

    private static Map<String, Object> buildClientMetadata(String clientId, ECKey ephemeralPublicKey) {

        Map<String, Object> clientMetadata = new HashMap<>();
        clientMetadata.put(Constants.METADATA_CLIENT_NAME, clientId);

        Map<String, Object> vcSdJwt = new HashMap<>();
        vcSdJwt.put(Constants.METADATA_SD_JWT_ALG_VALUES,
                Arrays.asList(VPConstants.Algorithms.ES256, VPConstants.Algorithms.EDDSA,
                        VPConstants.Algorithms.RS256));
        vcSdJwt.put(Constants.METADATA_KB_JWT_ALG_VALUES,
                Arrays.asList(VPConstants.Algorithms.ES256, VPConstants.Algorithms.EDDSA));
        Map<String, Object> vpFormats = new HashMap<>();
        vpFormats.put(VC_SD_JWT_FORMAT, vcSdJwt);
        clientMetadata.put(Constants.METADATA_VP_FORMATS, vpFormats);

        if (ephemeralPublicKey != null) {
            List<Object> keysList = new ArrayList<>();
            keysList.add(ephemeralPublicKey.toJSONObject());
            Map<String, Object> jwks = new HashMap<>();
            jwks.put(VPConstants.ClientMetadata.KEYS, keysList);
            clientMetadata.put(VPConstants.ClientMetadata.JWKS, jwks);
            clientMetadata.put(VPConstants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ALG,
                    VPConstants.Algorithms.ECDH_ES);
            clientMetadata.put(VPConstants.ClientMetadata.AUTHORIZATION_ENCRYPTED_RESPONSE_ENC,
                    VPConstants.Algorithms.A256GCM);
        }

        return clientMetadata;
    }

    private static char[] resolveKeyPassword(KeyStoreManager ksm, String tenantDomain)
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
}
