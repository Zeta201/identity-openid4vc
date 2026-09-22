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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant;

/**
 * Diagnostic log constants for the OpenID4VP authenticator.
 */
public class PresentationAuthenticatorLogConstants {

    private PresentationAuthenticatorLogConstants() {}

    public static final String VP_AUTHENTICATOR_COMPONENT_ID = "openid4vp-authenticator";

    /**
     * Action IDs representing key steps in the VP authentication flow.
     */
    public static class ActionIDs {

        public static final String INITIATE_VP_FLOW = "initiate-vp-flow";
        public static final String COMPLETE_VP_AUTHENTICATION = "complete-vp-authentication";
    }
}
