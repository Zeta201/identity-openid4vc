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

package org.wso2.carbon.identity.openid4vc.presentation.core.model;


/**
 * Tenant-level configuration for the OpenID4VP presentation flow.
 * Loaded from the configuration store by
 * {@link org.wso2.carbon.identity.openid4vc.presentation.core.service.PresentationConfigMgtService}
 * and applied when building presentation requests. Missing fields are filled with server
 * defaults before the config is returned to the caller.
 */
public class VPTenantConfig {

    /** {@code client_id_scheme} to use in presentation requests (e.g. {@code x509_san_dns}). */
    private String clientIdScheme;
    /** Response mode to request from the wallet ({@code direct_post} or {@code direct_post.jwt}). */
    private String responseMode;

    public String getClientIdScheme() {

        return clientIdScheme;
    }

    public void setClientIdScheme(String clientIdScheme) {

        this.clientIdScheme = clientIdScheme;
    }

    public String getResponseMode() {

        return responseMode;
    }

    public void setResponseMode(String responseMode) {

        this.responseMode = responseMode;
    }
}
