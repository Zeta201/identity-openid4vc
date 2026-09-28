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

package org.wso2.carbon.identity.openid4vc.presentation.verification.verifier;

import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

/**
 * This interface handles a single credential presentation format.
 */
public interface FormatVerifier {

    /**
     * Returns the credential format identifier this verifier handles.
     *
     * @return Credential format identifier.
     */
    String getFormat();

    /**
     * Verifies the credential token in the given context end-to-end.
     *
     * @param requestDTO Verification context carrying the raw token, request config, tenant, and nonce.
     * @return Verification response DTO carrying the verified credential metadata and subject claims.
     * @throws VerificationException If verification fails for any reason.
     */
    VerificationResponseDTO verifyCredential(VerificationRequestDTO requestDTO) throws VerificationException;
}
