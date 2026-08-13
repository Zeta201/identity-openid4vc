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

package org.wso2.carbon.identity.openid4vc.presentation.verification.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationClientException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationServerException;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Utility class for verifying cryptographic signatures of Verifiable Presentations and Credentials.
 */
public class SignatureVerifier {

    private static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    private static final String OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    private static final java.util.Set<String> ALLOWED_ALGORITHMS = java.util.Set.of(
            JWSAlgorithm.RS256.getName(),
            JWSAlgorithm.RS384.getName(),
            JWSAlgorithm.RS512.getName(),
            JWSAlgorithm.PS256.getName(),
            JWSAlgorithm.PS384.getName(),
            JWSAlgorithm.PS512.getName(),
            JWSAlgorithm.ES256.getName(),
            JWSAlgorithm.ES384.getName(),
            JWSAlgorithm.ES512.getName(),
            JWSAlgorithm.EdDSA.getName()
    );

    /**
     * Creates a utility class instance.
     *
     * <p>This constructor is intentionally private because this class exposes
     * only static utility methods.</p>
     */
    private SignatureVerifier() {

    }

    /**
     * Verifies a credential JWT signature against a pre-resolved JWKS JSON.
     * Extracts the algorithm from the JWT header; throws {@link VerificationClientException}
     * on an invalid signature or any parse failure.
     */
    public static void verifyCredentialSignature(String issuerJwt, String jwksJson)
            throws VerificationException {

        try {
            String signingAlgorithm = SignedJWT.parse(issuerJwt).getHeader().getAlgorithm().getName();
            if (signingAlgorithm == null || JWSAlgorithm.NONE.getName().equalsIgnoreCase(signingAlgorithm)
                    || !ALLOWED_ALGORITHMS.contains(signingAlgorithm)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "Unsupported or restricted JWS algorithm: " + signingAlgorithm);
            }
            if (!validateSignatureUsingInlineJwks(issuerJwt, jwksJson, signingAlgorithm)) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "Credential signature verification failed.");
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to verify credential signature: " + e.getMessage(), e);
        }
    }

    /**
     * Resolves a JWKS JSON string by fetching the given JWKS endpoint URI.
     * Returns {@code null} when no URI is configured.
     *
     * @param jwksUri JWKS endpoint URL configured on the credential, or {@code null}
     * @return The JWKS JSON string, or {@code null} when no URI is configured
     * @throws VerificationException If the URI fetch fails
     */
    public static String resolveJwksJson(String jwksUri) throws VerificationException {

        if (StringUtils.isNotBlank(jwksUri)) {
            try {
                return HttpClientUtil.fetchContent(jwksUri, null);
            } catch (Exception e) {
                throw new VerificationServerException(VerificationErrorCode.JWKS_RESOLUTION_ERROR,
                        "Failed to fetch JWKS from URI: " + jwksUri + " — " + e.getMessage(), e);
            }
        }
        return null;
    }

    /**
     * Validates a JWT signature using a pre-resolved JWKS JSON string.
     * Unlike {@code validateSignatureUsingJwks}, this method does not perform any
     * network calls — the caller is responsible for supplying the JWKS content.
     *
     * @param jwtString The raw compact JWT string
     * @param jwksJson  The JWKS JSON (inline payload or previously fetched from the endpoint)
     * @param algorithm The expected JWS algorithm identifier
     * @return {@code true} if the signature validates successfully
     * @throws VerificationException If validation fails for any reason
     */
    public static boolean validateSignatureUsingInlineJwks(String jwtString, String jwksJson, String algorithm)
            throws VerificationException {

        try {
            JWKSet jwkSet = JWKSet.parse(jwksJson);
            JWKSource<SecurityContext> jwkKeySource = new ImmutableJWKSet<>(jwkSet);

            ConfigurableJWTProcessor<SecurityContext> jwtSignatureProcessor = new DefaultJWTProcessor<>();
            jwtSignatureProcessor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier<>(
                            new JOSEObjectType(VerificationConstants.JOSE_TYPE_JWT),
                            JOSEObjectType.JWT,
                            new JOSEObjectType(Constants.VC_SD_JWT_FORMAT)
                    )
            );

            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(algorithm);
            JWSKeySelector<SecurityContext> jwsKeySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, jwkKeySource);
            jwtSignatureProcessor.setJWSKeySelector(jwsKeySelector);

            jwtSignatureProcessor.process(jwtString, null);
            return true;

        } catch (java.text.ParseException e) {
            throw new VerificationServerException(VerificationErrorCode.PARSE_ERROR,
                    "Failed to parse JWKS JSON", e);
        } catch (BadJOSEException | JOSEException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Signature verification failed: " + e.getMessage(), e);
        }
    }

    /**
         * Verifies a JWT signature using a provided public key and JWS algorithm.
         *
         * @param jwtString The raw compact JWT string
         * @param publicKey The public key used for signature verification
         * @param algorithm The expected JWS algorithm identifier
         * @return {@code true} if the signature is valid; otherwise {@code false}
         * @throws VerificationException If verification fails due to parsing or JOSE errors
     */
    public static boolean verifySignatureWithPublicKey(String jwtString, PublicKey publicKey, String algorithm)
            throws VerificationException {

        // Allowlist check must come first — callers derive `algorithm` from the attacker-controlled
        // JWT header, so without this gate the mismatch check below is trivially bypassed.
        if (algorithm == null || JWSAlgorithm.NONE.getName().equalsIgnoreCase(algorithm)
                || !ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Unsupported or restricted JWS algorithm: " + algorithm);
        }
        try {
            SignedJWT signedJwt = SignedJWT.parse(jwtString);

            // Prevent algorithm-switching: the JWT header must agree with the pre-validated alg.
            if (!algorithm.equals(signedJwt.getHeader().getAlgorithm().getName())) {
                throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                        "JWS algorithm mismatch. Expected: " + algorithm + ", Actual: " +
                                signedJwt.getHeader().getAlgorithm().getName());
            }

            JWSVerifier jwsVerifier = new DefaultJWSVerifierFactory().createJWSVerifier(
                    signedJwt.getHeader(), publicKey);
            return signedJwt.verify(jwsVerifier);
        } catch (JOSEException | ParseException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to verify JWT signature: " + e.getMessage(), e);
        }
    }

    /**
     * Decodes a Nimbus Base64-encoded x5c certificate chain into a list of {@link X509Certificate}s.
     *
     * @param x5cChain Base64-encoded certificates from the JWT {@code x5c} header
     * @return Ordered list of decoded certificates (leaf first)
     * @throws VerificationClientException If any entry cannot be decoded as an X.509 certificate
     */
    public static List<X509Certificate> decodeCertChain(List<com.nimbusds.jose.util.Base64> x5cChain)
            throws VerificationClientException {

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
            List<X509Certificate> certChain = new ArrayList<>();
            for (com.nimbusds.jose.util.Base64 encodedCert : x5cChain) {
                certChain.add((X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(encodedCert.decode())));
            }
            return certChain;
        } catch (java.security.cert.CertificateException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Failed to decode x5c certificate chain: " + e.getMessage(), e);
        }
    }

    /**
     * Validates an x5c certificate chain from a JWT header against the WSO2 IS trust store
     * ({@code client-truststore.p12}).
     *
     * <p>Checks performed:
     * <ol>
     *   <li>Validity period ({@code notBefore}/{@code notAfter}) of every certificate.</li>
     *   <li>PKIX chain integrity — the full chain is validated against the IS trust store,
     *       not against the last cert in the presenter-supplied chain.  This prevents an
     *       attacker from supplying a self-signed chain that validates against itself.</li>
     * </ol>
     *
     * <p>Revocation (CRL/OCSP) is intentionally disabled because no network endpoint
     * is guaranteed to be reachable at verification time.
     *
     * @param certificateChain Ordered list of certificates: {@code [leaf, intermediate..., root]}
     * @throws VerificationException If any certificate has expired, is not yet valid,
     *                               or the chain fails PKIX validation against the trust store
     */
    public static void validateX5cChain(List<X509Certificate> certificateChain) throws VerificationException {

        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c certificate chain is empty.");
        }
        try {
            for (X509Certificate cert : certificateChain) {
                cert.checkValidity();
            }

            Set<TrustAnchor> trustAnchors = buildIsTrustAnchors();
            CertificateFactory certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
            CertPath certPath = certFactory.generateCertPath(certificateChain);

            PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false);

            CertPathValidator.getInstance(VerificationConstants.JCA_PKIX).validate(certPath, pkixParams);

        } catch (java.security.cert.CertificateExpiredException e) {
            throw new VerificationClientException(VerificationErrorCode.EXPIRED_CREDENTIAL,
                    "A certificate in the x5c chain has expired: " + e.getMessage(), e);
        } catch (java.security.cert.CertificateNotYetValidException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "A certificate in the x5c chain is not yet valid: " + e.getMessage(), e);
        } catch (java.security.cert.CertPathValidatorException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c certificate chain does not root to a trusted CA: " + e.getMessage(), e);
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Unexpected error during x5c chain validation: " + e.getMessage(), e);
        }
    }

    /**
     * Validates an x5c chain against an explicit trust anchor rather than the server-wide trust store.
     *
     * <p>Used by {@code X5cSignatureValidator} with the per-definition {@code trustedCaPem} field so
     * that each presentation definition can restrict which CA it accepts — required for Asgardeo
     * where tenants cannot modify the server file system.
     *
     * @param certificateChain Ordered list: {@code [leaf, intermediate..., (no root)]}
     * @param trustAnchorCert The root CA certificate to validate against (from {@code trustedCaPem}).
     * @throws VerificationException If the chain is empty, a cert has expired/is not yet valid,
     *                               or PKIX validation fails.
     */
    public static void validateX5cChain(List<X509Certificate> certificateChain, X509Certificate trustAnchorCert)
            throws VerificationException {

        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c certificate chain is empty.");
        }
        if (trustAnchorCert == null) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "No trust anchor certificate provided for x5c chain validation.");
        }
        try {
            for (X509Certificate cert : certificateChain) {
                cert.checkValidity();
            }
            Set<TrustAnchor> trustAnchors = Collections.singleton(new TrustAnchor(trustAnchorCert, null));
            CertificateFactory certFactory = CertificateFactory.getInstance(VerificationConstants.JCA_X509);
            CertPath certPath = certFactory.generateCertPath(certificateChain);
            PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false);
            CertPathValidator.getInstance(VerificationConstants.JCA_PKIX).validate(certPath, pkixParams);
        } catch (java.security.cert.CertificateExpiredException e) {
            throw new VerificationClientException(VerificationErrorCode.EXPIRED_CREDENTIAL,
                    "A certificate in the x5c chain has expired: " + e.getMessage(), e);
        } catch (java.security.cert.CertificateNotYetValidException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_CREDENTIAL,
                    "A certificate in the x5c chain is not yet valid: " + e.getMessage(), e);
        } catch (java.security.cert.CertPathValidatorException e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "x5c certificate chain does not root to the configured trusted CA: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new VerificationClientException(VerificationErrorCode.INVALID_SIGNATURE,
                    "Unexpected error during x5c chain validation: " + e.getMessage(), e);
        }
    }

    /**
     * Loads trust anchors from the WSO2 IS trust store ({@code client-truststore.p12}).
     * Location, password, and type are read from {@link ServerConfiguration} so that
     * deployment-specific CAs added by administrators are automatically honoured.
     */
    private static Set<TrustAnchor> buildIsTrustAnchors() throws VerificationException {

        try {
            ServerConfiguration serverConfig = ServerConfiguration.getInstance();
            String trustStoreLocation = serverConfig.getFirstProperty(VerificationConstants.CONFIG_TRUSTSTORE_LOCATION);
            String trustStorePassword = serverConfig.getFirstProperty(VerificationConstants.CONFIG_TRUSTSTORE_PASSWORD);
            String trustStoreType = serverConfig.getFirstProperty(VerificationConstants.CONFIG_TRUSTSTORE_TYPE);
            if (trustStoreLocation == null || trustStorePassword == null) {
                throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                        "IS trust store location or password is not configured.");
            }
            KeyStore trustStore = KeyStore.getInstance(
                    trustStoreType != null ? trustStoreType : VerificationConstants.JCA_PKCS12);
            try (FileInputStream trustStoreStream = new FileInputStream(trustStoreLocation)) {
                trustStore.load(trustStoreStream, trustStorePassword.toCharArray());
            }
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (trustStore.isCertificateEntry(alias)) {
                    Certificate cert = trustStore.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        trustAnchors.add(new TrustAnchor((X509Certificate) cert, null));
                    }
                }
            }
            if (trustAnchors.isEmpty()) {
                throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                        "No trust anchors found in the IS trust store at: " + trustStoreLocation);
            }
            return trustAnchors;
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationServerException(VerificationErrorCode.INTERNAL_SERVER_ERROR,
                    "Failed to load the IS trust store.", e);
            }
        }

    /**
     * Extracts the raw KeyIdentifier bytes from the AuthorityKeyIdentifier extension (OID 2.5.29.35).
     * Returns {@code null} if the extension is absent or contains no keyIdentifier component.
     *
     * <p>DER layout returned by {@code getExtensionValue}:
     * {@code 04[outerLen] 30[seqLen] 80[kidLen] [kid_bytes]}
     */
    public static byte[] extractAkiKeyIdentifier(X509Certificate cert) {

        byte[] extensionValue = cert.getExtensionValue(OID_AUTHORITY_KEY_IDENTIFIER);
        if (extensionValue == null || extensionValue.length < 7) {
            return null;
        }
        try {
            // [0]=0x04 outer OCTET STRING, [2]=0x30 SEQUENCE, [4]=0x80 context[0] (keyIdentifier)
            if (extensionValue[0] != 0x04 || extensionValue[2] != 0x30 || extensionValue[4] != (byte) 0x80) {
                return null;
            }
            int keyIdentifierLength = extensionValue[5] & 0xFF;
            if (extensionValue.length < 6 + keyIdentifierLength) {
                return null;
            }
            byte[] keyIdentifierBytes = new byte[keyIdentifierLength];
            System.arraycopy(extensionValue, 6, keyIdentifierBytes, 0, keyIdentifierLength);
            return keyIdentifierBytes;
        } catch (ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Extracts the raw SubjectKeyIdentifier bytes from a certificate (OID 2.5.29.14).
     * Returns {@code null} if the extension is absent or malformed.
     *
     * <p>DER layout: {@code 04[outerLen] 04[innerLen] [ski_bytes]}
     */
    public static byte[] extractSkiBytes(X509Certificate cert) {

        byte[] extensionValue = cert.getExtensionValue(OID_SUBJECT_KEY_IDENTIFIER);
        if (extensionValue == null || extensionValue.length < 5) {
            return null;
        }
        try {
            if (extensionValue[0] != 0x04 || extensionValue[2] != 0x04) {
                return null;
            }
            int subjectKeyIdentifierLength = extensionValue[3] & 0xFF;
            if (extensionValue.length < 4 + subjectKeyIdentifierLength) {
                return null;
            }
            byte[] subjectKeyIdentifierBytes = new byte[subjectKeyIdentifierLength];
            System.arraycopy(extensionValue, 4, subjectKeyIdentifierBytes, 0, subjectKeyIdentifierLength);
            return subjectKeyIdentifierBytes;
        } catch (ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

}
