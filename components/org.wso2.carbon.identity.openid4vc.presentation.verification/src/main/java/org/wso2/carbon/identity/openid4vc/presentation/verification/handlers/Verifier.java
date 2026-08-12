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

package org.wso2.carbon.identity.openid4vc.presentation.verification.handlers;

import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationContext;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;

/**
 * Pluggable handler for a single credential presentation format.
 *
 * <p>Each implementation owns all format-specific logic end-to-end:
 * token parsing, signature validation, claim extraction, holder binding,
 * type enforcement, metadata extraction, and technical claim stripping.
 * The service layer only routes to the right handler and enforces
 * format-agnostic policy (claim constraints).
 */
public interface Verifier {

    /**
     * Returns the credential format identifier this verifier handles
     * (e.g. {@code dc+sd-jwt}).
     */
    String getFormat();

    /**
     * Verifies the credential token in the given context end-to-end.
     *
     * @param ctx verification context carrying the raw token, request config, tenant, and nonce
     * @return {@link PresentationMetadata} containing the verified subject-attribute claims and structured metadata
     * @throws VerificationException if verification fails for any reason
     */
    PresentationMetadata verify(CredentialVerificationContext ctx) throws VerificationException;
}
