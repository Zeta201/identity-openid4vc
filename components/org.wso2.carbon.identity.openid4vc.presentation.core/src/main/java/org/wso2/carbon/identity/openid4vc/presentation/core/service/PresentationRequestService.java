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

package org.wso2.carbon.identity.openid4vc.presentation.core.service;

import org.wso2.carbon.identity.openid4vc.presentation.core.exception.PresentationCoreException;

/**
 * This interface builds and signs the OpenID4VP authorization request JWT.
 */
public interface PresentationRequestService {

    /**
     * Generates the signed presentation request JWT for a VP flow session.
     *
     * @param requestId    VP session request ID.
     * @param tenantDomain Tenant domain resolved from the request URL.
     * @return Signed request JWT.
     * @throws PresentationCoreException If the session is not found or the JWT cannot be built.
     */
    String buildPresentationRequest(String requestId, String tenantDomain) throws PresentationCoreException;
}
