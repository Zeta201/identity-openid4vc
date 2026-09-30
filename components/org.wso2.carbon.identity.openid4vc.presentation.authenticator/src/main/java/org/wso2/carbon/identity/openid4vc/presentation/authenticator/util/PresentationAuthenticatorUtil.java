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
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for VP server related operations.
 */
public class PresentationAuthenticatorUtil {

    private static final Log LOG = LogFactory.getLog(PresentationAuthenticatorUtil.class);

    private PresentationAuthenticatorUtil() {

    }

    /**
     * Resolves the subject identifier for the authenticated user from the verified credential claims.
     *
     * @param subjectClaims    Claims extracted from the verified credential.
     * @param subjectClaimName Remote claim URI configured as the subject attribute; may be null.
     * @param metadata         Presentation metadata carrying the issuer identifier; may be null.
     * @return Namespaced subject identifier, or null if not resolvable.
     */
    public static String resolveSubjectIdentifier(Map<String, Object> subjectClaims,
                                                   String subjectClaimName,
                                                   VerificationResponseDTO metadata) {

        // 1. Configured subject attribute claim.
        if (StringUtils.isNotBlank(subjectClaimName)) {
            Object val = subjectClaims.get(subjectClaimName);
            if (val != null && StringUtils.isNotBlank(val.toString())) {
                return qualifyWithIssuer(val.toString(), metadata);
            }
            LOG.warn("Configured subject attribute '" + subjectClaimName
                    + "' was not found in the verified credential claims; falling back to cnf.");
        }

        // 2. cnf (holder-binding) claim — the VC equivalent of OIDC's sub.
        String cnfIdentifier = resolveSubjectFromCnf(subjectClaims);
        if (cnfIdentifier != null) {
            return qualifyWithIssuer(cnfIdentifier, metadata);
        }

        return null;
    }

    /**
     * Extracts a stable string identifier from the cnf (confirmation) claim.
     */
    private static String resolveSubjectFromCnf(Map<String, Object> verifiedClaims) {

        Object cnfRaw = verifiedClaims.get(Constants.JWTClaims.CNF);
        if (cnfRaw == null) {
            return null;
        }
        if (cnfRaw instanceof Map) {
            Map<?, ?> cnf = (Map<?, ?>) cnfRaw;
            Object jktRaw = cnf.get(Constants.JWTClaims.JKT);
            // cnf.jkt (JWK thumbprint) — SHA-256 of the key
            return jktRaw != null ? StringUtils.trimToNull(jktRaw.toString()) : null;
        } else {
            // cnf as a plain string (e.g. a DID)
            return StringUtils.trimToNull(cnfRaw.toString());
        }
    }

    /**
     * Qualifies a subject identifier value with the credential issuer to prevent cross-issuer collisions.
     *
     * @param value    Raw subject identifier extracted from the credential claim.
     * @param metadata Presentation metadata carrying the issuer; may be null.
     * @return Issuer-qualified identifier, or value if the issuer is unavailable.
     */
    private static String qualifyWithIssuer(String value, VerificationResponseDTO metadata) {

        if (metadata != null && StringUtils.isNotBlank(metadata.getIssuer())) {
            return metadata.getIssuer() + "#" + value;
        }
        return value;
    }

    /**
     * Returns the remote VP claim name configured as the Subject Attribute on the IdP's Attributes tab.
     *
     * @param externalIdPConfig External IdP configuration; may be null.
     * @return Configured subject claim URI, or null if none is set.
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
     * Builds the federated user attribute map from the verified credential claims using the IdP claim mappings.
     *
     * @param subjectClaims Subject-attribute claims extracted from the verified credential.
     * @param idpConfig     IdP configuration carrying the claim mappings, or null.
     * @return Map of claim mappings to claim value strings, ready for the authenticated user.
     */
    public static Map<ClaimMapping, String> buildUserAttributes(Map<String, Object> subjectClaims,
                                                                ExternalIdPConfig idpConfig) {

        Map<ClaimMapping, String> federatedAttributes = new HashMap<>();
        ClaimMapping[] claimMappings = (idpConfig != null
                && idpConfig.getIdentityProvider() != null
                && idpConfig.getIdentityProvider().getClaimConfig() != null)
                ? idpConfig.getIdentityProvider().getClaimConfig().getClaimMappings() : null;

        if (claimMappings == null) {
            return federatedAttributes;
        }

        for (ClaimMapping claimMapping : claimMappings) {
            if (claimMapping.getRemoteClaim() == null || claimMapping.getLocalClaim() == null
                    || StringUtils.isBlank(claimMapping.getRemoteClaim().getClaimUri())
                    || StringUtils.isBlank(claimMapping.getLocalClaim().getClaimUri())) {
                continue;
            }
            Object value = subjectClaims.get(claimMapping.getRemoteClaim().getClaimUri());
            if (value != null && StringUtils.isNotBlank(value.toString())) {
                federatedAttributes.put(ClaimMapping.build(
                        claimMapping.getLocalClaim().getClaimUri(),
                        claimMapping.getRemoteClaim().getClaimUri(), null, false), value.toString());
            }
        }
        return federatedAttributes;
    }
}
