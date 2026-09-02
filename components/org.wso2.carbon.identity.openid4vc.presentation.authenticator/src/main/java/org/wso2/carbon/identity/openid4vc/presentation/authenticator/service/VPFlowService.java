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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.service;

import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.exception.VPAuthenticatorServerException;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowInitiationResult;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;

/**
 * OSGi service for VP flow session management (standalone verification and self-registration flows).
 */
public interface VPFlowService {

    /**
     * Initiates a new VP flow session for standalone verification or self-registration.
     * A random request ID is generated internally.
     *
     * @param presentationDefinitionId the ID of the presentation definition to request
     * @param tenantDomain             the tenant domain for the request
     * @return initiation result containing the request ID, wallet URL, request URI, and expiry timestamp
     * @throws VPAuthenticatorException if the configuration or presentation definition lookup fails
     */
    VPFlowInitiationResult initiate(String presentationDefinitionId, String tenantDomain)
            throws VPAuthenticatorException;

    /**
     * Initiates a new VP flow session for the authentication flow with a caller-supplied request ID
     * and configurable timeout.
     *
     * @param requestId                the caller-supplied transaction ID for this VP session
     * @param presentationDefinitionId the ID of the presentation definition to request
     * @param tenantDomain             the tenant domain for the request
     * @param timeoutMs                the session TTL in milliseconds
     * @return initiation result containing the request ID, wallet URL, request URI, and expiry timestamp
     * @throws VPAuthenticatorException if the configuration or presentation definition lookup fails
     */
    VPFlowInitiationResult initiate(String requestId, String presentationDefinitionId, String tenantDomain,
            long timeoutMs) throws VPAuthenticatorException;

    /**
     * Generates the signed request JWT for a VP flow session, served to the wallet via {@code request_uri}.
     *
     * @param requestId the transaction ID of the VP session
     * @return the signed request JWT string
     * @throws VPAuthenticatorException if the session is not found or the JWT cannot be built
     */
    String createAuthorizationRequestJwt(String requestId) throws VPAuthenticatorException;

    /**
     * Looks up a VP flow session by its transaction ID.
     *
     * @param requestId the transaction ID of the VP session
     * @return the session for the given request ID, or {@code null} if not found or expired
     * @throws VPAuthenticatorServerException If the database read or secret decryption fails
     */
    VPFlowSession getSession(String requestId) throws VPAuthenticatorServerException;

    /**
     * Removes a VP flow session from the cache, releasing any stored PII.
     * Called after a terminal state (VERIFIED or FAILED) has been consumed by the caller.
     *
     * @param requestId the transaction ID of the VP session to remove
     */
    void removeSession(String requestId);
}
