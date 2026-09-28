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

package org.wso2.carbon.identity.openid4vc.presentation.core.constant;

/**
 * Constants for the OpenID for Verifiable Presentations (OpenID4VP) presentation core module.
 */
public final class PresentationCoreConstants {

    public static final String AUTHENTICATOR_NAME = "PresentationAuthenticator";

    public static final String RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt";
    public static final String DEFAULT_CLIENT_ID_SCHEME = "x509_san_dns";

    public static final String CONTEXT_OID4VP_REQUESTS = "/oid4vp/requests";
    public static final String CONTEXT_OID4VP_RESPONSES = "/oid4vp/responses";
    public static final String CLAIM_CLIENT_METADATA = "client_metadata";
    public static final String METADATA_CLIENT_NAME = "client_name";
    public static final String METADATA_VP_FORMATS = "vp_formats";
    public static final String METADATA_SD_JWT_ALG_VALUES = "sd-jwt_alg_values";
    public static final String METADATA_KB_JWT_ALG_VALUES = "kb-jwt_alg_values";
    public static final String JOSE_TYPE_OAUTH_AUTHZ_REQ = "oauth-authz-req+jwt";
    public static final String JCA_X509 = "X.509";

    private PresentationCoreConstants() { }
}
