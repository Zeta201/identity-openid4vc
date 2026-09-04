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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.util.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.listener.AbstractIdentityProviderMgtListener;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;

/**
 * Provisions an ECDSA keypair into the tenant keystore whenever a new IdP backed by
 * {@code VPAuthenticator} is created.
 */
public class VPIdPManagementListener extends AbstractIdentityProviderMgtListener {

    private static final Log LOG = LogFactory.getLog(VPIdPManagementListener.class);

    private static final String EC_ALGORITHM = "EC";
    private static final String EC_CURVE = "secp256r1";
    private static final String SIGN_ALGORITHM = "SHA256withECDSA";

    @Override
    public int getDefaultOrderId() {

        return 110;
    }

    @Override
    public boolean doPostAddIdP(IdentityProvider identityProvider, String tenantDomain)
            throws IdentityProviderManagementException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(VPConstants.ConfigKeys.FEATURE_ENABLED))) {
            return true;
        }

        if (!isOid4vpIdP(identityProvider)) {
            return true;
        }

        try {
            provisionEcdsaKeyPairIfAbsent(tenantDomain);
        } catch (Exception e) {
            throw new IdentityProviderManagementException(
                    "Failed to provision ECDSA keypair for tenant [" + tenantDomain
                    + "]. VP request signing would be unavailable — IdP creation aborted.", e);
        }

        return true;
    }

    /**
     * Returns {@code true} if the given identity provider is backed by the VP authenticator.
     *
     * @param identityProvider the IdP to inspect
     * @return {@code true} if any federated authenticator config matches the VP authenticator name
     */
    private boolean isOid4vpIdP(IdentityProvider identityProvider) {

        if (identityProvider == null) {
            return false;
        }
        FederatedAuthenticatorConfig[] authenticatorConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        if (authenticatorConfigs == null) {
            return false;
        }
        return Arrays.stream(authenticatorConfigs)
                .anyMatch(authenticatorConfig -> Constants.AUTHENTICATOR_NAME.equals(authenticatorConfig.getName()));
    }

    /**
     * Ensures that a P-256 ECDSA keypair exists in the tenant keystore under the VP alias.
     * If the alias is already present the method returns without making any changes.
     *
     * @param tenantDomain the tenant domain whose keystore should be provisioned
     * @throws Exception if the keystore cannot be read, the keypair cannot be generated,
     *                   or the keystore cannot be persisted
     */
    private void provisionEcdsaKeyPairIfAbsent(String tenantDomain) throws Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        String keyStoreName = resolveKeyStoreName(tenantDomain);
        KeyStore keyStore = keyStoreManager.getKeyStore(keyStoreName);
        String alias = KeyStoreUtil.getTenantECKeyAlias(tenantDomain);

        if (keyStore.containsAlias(alias) && keyStore.isKeyEntry(alias)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("ECDSA alias already exists for tenant " + tenantDomain + ". Skipping.");
            }
            return;
        }

        LOG.info("Generating P-256 ECDSA keypair for tenant " + tenantDomain + ".");

        CryptoUtil.getDefaultCryptoUtil();

        KeyPair keyPair = generateEcKeyPair();

        X509Certificate cert = buildSelfSignedCert(keyPair, tenantDomain);

        char[] keyPassword = keyStoreManager.getPrivateKeyPassword(keyStoreName);
        try {
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword, new Certificate[]{cert});
            keyStoreManager.updateKeyStore(keyStoreName, keyStore);
        } finally {
            if (keyPassword != null) {
                Arrays.fill(keyPassword, '\0');
            }
        }

        LOG.info("ECDSA P-256 keypair provisioned for tenant " + tenantDomain + ".");
    }

    /**
     * Returns the keystore file name for the given tenant domain.
     * The super-tenant uses the default keystore; all other tenants use a JKS file
     * derived from the tenant domain.
     *
     * @param tenantDomain the tenant domain
     * @return the keystore file name
     */
    private String resolveKeyStoreName(String tenantDomain) {

        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return KeyStoreUtil.getKeyStoreFileName(null);
        }
        return tenantDomain.trim().replace(".", "-") + ".jks";
    }

    /**
     * Generates a P-256 (secp256r1) EC keypair using the configured JCA provider.
     *
     * @return the generated {@link KeyPair}
     * @throws GeneralSecurityException if the EC algorithm or curve is not available
     */
    private KeyPair generateEcKeyPair() throws GeneralSecurityException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM);
        keyPairGenerator.initialize(new ECGenParameterSpec(EC_CURVE));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Builds a self-signed X.509 certificate for the given keypair and tenant.
     * The certificate is valid for 10 years and includes a DNS SAN set to the tenant domain.
     *
     * @param keyPair      the keypair whose public key will be embedded in the certificate
     * @param tenantDomain the tenant domain; used as the CN and as the DNS SAN value
     * @return the self-signed {@link X509Certificate}
     * @throws GeneralSecurityException   if the JCA/JCE operations fail
     * @throws CertIOException            if the SAN extension cannot be encoded
     * @throws OperatorCreationException  if the content signer cannot be built
     */
    private X509Certificate buildSelfSignedCert(KeyPair keyPair, String tenantDomain)
            throws GeneralSecurityException, CertIOException, OperatorCreationException {

        String subjectDnString = "CN=" + tenantDomain + ", OU=None, O=None, L=None, C=None";
        X500Name subjectDn = new X500Name(subjectDnString);

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10);
        BigInteger serial = new BigInteger(32, new SecureRandom());

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subjectDn, serial, notBefore, notAfter, subjectDn, publicKeyInfo);
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, tenantDomain)));

        String bouncyCastleProvider = CryptoUtil.getJCEProvider();
        ContentSigner signer = new JcaContentSignerBuilder(SIGN_ALGORITHM)
                .setProvider(bouncyCastleProvider)
                .build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(bouncyCastleProvider)
                .getCertificate(certificateHolder);
    }

}
