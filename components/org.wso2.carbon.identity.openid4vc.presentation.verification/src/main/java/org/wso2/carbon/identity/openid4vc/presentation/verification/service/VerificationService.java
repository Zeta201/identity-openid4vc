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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.VerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.util.Map;

/**
 * Service interface for Verifiable Credential verification.
 */
public interface VerificationService {

    /**
     * Verifies a DCQL VP response against a pre-loaded {@link PresentationDefinition}.
     *
     * @param definition       the presentation definition used to issue the VP request
     * @param tenantId         the tenant identifier
     * @param presentation     the parsed DCQL vp_token — a map of credential query ID to credential token
     * @param expectedNonce    the nonce sent in the VP request; {@code null} skips nonce validation
     * @param expectedAudience the verifier's {@code client_id} from the Authorization Request; used to
     *                         validate the {@code aud} claim in the KB-JWT; {@code null} skips audience
     *                         validation, which is only acceptable when holder binding is not required
     * @return the verification outcome
     * @throws VerificationException if verification fails critically
     */
    VerificationResult verify(PresentationDefinition definition, int tenantId,
                               Map<String, String> presentation, String expectedNonce,
                               String expectedAudience)
            throws VerificationException;
}
