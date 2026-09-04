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

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps a stored {@link PresentationDefinition} to a runtime {@link DcqlQuery}.
 *
 * <p>This is the boundary between the template-management storage model and the verification
 * execution model. Callers fetch a {@code PresentationDefinition} from the DB and pass the
 * resulting {@code DcqlQuery} to {@code VerificationService.verify()}.
 */
public class DcqlQueryMapper {

    private DcqlQueryMapper() {

    }

    /**
     * Converts a {@link PresentationDefinition} into a {@link DcqlQuery}.
     *
     * @param definition the stored presentation definition
     * @return the equivalent DCQL query for verification
     */
    public static DcqlQuery from(PresentationDefinition definition) {

        List<PresentationDefinition.RequestedCredential> requestedCredentials =
                definition.getRequestedCredentials();
        List<DcqlQuery.CredentialQuery> credentialQueries = new ArrayList<>();
        if (requestedCredentials != null) {
            for (PresentationDefinition.RequestedCredential rc : requestedCredentials) {
                credentialQueries.add(mapCredentialQuery(rc));
            }
        }
        return new DcqlQuery.Builder()
                .credentials(credentialQueries)
                .build();
    }

    private static DcqlQuery.CredentialQuery mapCredentialQuery(
            PresentationDefinition.RequestedCredential rc) {

        List<DcqlQuery.IssuerConfig> issuerConfigs = null;
        if (rc.getIssuerConfigs() != null) {
            issuerConfigs = new ArrayList<>();
            for (PresentationDefinition.IssuerConfig ic : rc.getIssuerConfigs()) {
                issuerConfigs.add(
                        new DcqlQuery.IssuerConfig(ic.getKeySourceType(), ic.getIssuerUrl(), ic.getKeySource()));
            }
        }

        List<DcqlQuery.ClaimQuery> claims = null;
        if (rc.getClaims() != null) {
            claims = new ArrayList<>();
            for (PresentationDefinition.ClaimConstraint cc : rc.getClaims()) {
                claims.add(new DcqlQuery.ClaimQuery(cc.getPath(), cc.isMandatory()));
            }
        }

        return new DcqlQuery.CredentialQuery.Builder()
                .id(rc.getIdentifier())
                .format(rc.getFormat())
                .vct(rc.getType())
                .issuerConfigs(issuerConfigs)
                .claims(claims)
                .build();
    }

}
