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

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Converts a {@link DcqlQuery} into the {@code Map<String, Object>} structure required
 * for embedding as the {@code dcql_query} claim in the OpenID4VP authorization request JWT.
 */
public class DcqlQuerySerializer {

    private DcqlQuerySerializer() {

    }

    /**
     * Serializes a {@link DcqlQuery} to a map ready for use as a JWT claim.
     *
     * @param query the DCQL query to serialize; if {@code null} an empty credentials map is returned
     * @return map representing the full DCQL query structure
     */
    public static Map<String, Object> toMap(DcqlQuery query) {

        List<Map<String, Object>> credentials = new ArrayList<>();

        if (query != null && query.getCredentials() != null) {
            for (DcqlQuery.CredentialQuery cred : query.getCredentials()) {
                if (cred == null) {
                    continue;
                }
                credentials.add(serializeCredential(cred));
            }
        }

        Map<String, Object> dcql = new HashMap<>();
        dcql.put(VPConstants.DCQL.CREDENTIALS, credentials);

        if (!credentials.isEmpty()) {
            List<String> allCredIds = new ArrayList<>();
            for (Map<String, Object> cred : credentials) {
                allCredIds.add((String) cred.get(VPConstants.DCQL.ID));
            }
            Map<String, Object> credSet = new HashMap<>();
            credSet.put(VPConstants.DCQL.OPTIONS, Collections.singletonList(allCredIds));
            dcql.put(VPConstants.DCQL.CREDENTIAL_SETS, Collections.singletonList(credSet));
        }

        return dcql;
    }

    private static Map<String, Object> serializeCredential(DcqlQuery.CredentialQuery cred) {

        Map<String, Object> dcqlCred = new HashMap<>();
        dcqlCred.put(VPConstants.DCQL.ID, cred.getId());
        dcqlCred.put(VPConstants.DCQL.FORMAT, cred.getFormat());

        if (!StringUtils.isBlank(cred.getVct())) {
            Map<String, Object> meta = new HashMap<>();
            meta.put(VPConstants.DCQL.VCT_VALUES, Collections.singletonList(cred.getVct()));
            dcqlCred.put(VPConstants.DCQL.META, meta);
        }

        List<Map<String, Object>> claimsList = new ArrayList<>();
        List<String> mandatoryClaimIds = new ArrayList<>();
        boolean hasOptionalClaims = false;

        if (cred.getClaims() != null) {
            for (DcqlQuery.ClaimQuery claim : cred.getClaims()) {
                if (claim == null || StringUtils.isBlank(claim.getPath())) {
                    continue;
                }
                String[] pathSegments = claim.getPath().split("\\.");
                String claimId = String.join("_", pathSegments);

                Map<String, Object> claimMap = new HashMap<>();
                claimMap.put(VPConstants.DCQL.ID, claimId);
                claimMap.put(VPConstants.DCQL.PATH, Arrays.asList(pathSegments));
                claimsList.add(claimMap);

                if (claim.isMandatory()) {
                    mandatoryClaimIds.add(claimId);
                } else {
                    hasOptionalClaims = true;
                }
            }
        }
        if (!claimsList.isEmpty()) {
            dcqlCred.put(VPConstants.DCQL.CLAIMS, claimsList);
        }
        if (hasOptionalClaims && !mandatoryClaimIds.isEmpty()) {
            List<String> allClaimIds = new ArrayList<>();
            for (Map<String, Object> claimMap : claimsList) {
                allClaimIds.add((String) claimMap.get(VPConstants.DCQL.ID));
            }
            List<List<String>> autoSets = new ArrayList<>();
            autoSets.add(allClaimIds);
            autoSets.add(mandatoryClaimIds);
            dcqlCred.put(VPConstants.DCQL.CLAIM_SETS, autoSets);
        }

        serializeTrustedAuthorities(cred, dcqlCred);

        return dcqlCred;
    }

    private static void serializeTrustedAuthorities(DcqlQuery.CredentialQuery cred,
            Map<String, Object> dcqlCred) {

        if (cred.getIssuerConfigs() == null || cred.getIssuerConfigs().isEmpty()) {
            return;
        }
        List<String> allAkiValues = new ArrayList<>();
        for (DcqlQuery.IssuerConfig ic : cred.getIssuerConfigs()) {
            if (!"x5c".equalsIgnoreCase(ic.getKeySourceType())) {
                continue;
            }
            List<String> aki = ic.getAkiValues();
            if (aki != null) {
                allAkiValues.addAll(aki);
            }
        }
        if (!allAkiValues.isEmpty()) {
            Map<String, Object> trustedAuthority = new HashMap<>();
            trustedAuthority.put(VPConstants.DCQL.TRUSTED_AUTHORITY_TYPE,
                    VPConstants.DCQL.TRUSTED_AUTHORITY_TYPE_AKI);
            trustedAuthority.put(VPConstants.DCQL.TRUSTED_AUTHORITY_VALUES, allAkiValues);
            dcqlCred.put(VPConstants.DCQL.TRUSTED_AUTHORITIES,
                    Collections.singletonList(trustedAuthority));
        }
    }
}
