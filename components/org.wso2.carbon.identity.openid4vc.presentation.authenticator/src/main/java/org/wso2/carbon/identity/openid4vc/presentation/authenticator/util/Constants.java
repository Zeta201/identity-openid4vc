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

/**
 * Constants for the OpenID for Verifiable Presentations (OpenID4VP) presentation server.
 */
public class Constants {

    public static final String AUTHENTICATOR_NAME = "VPAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Wallet (OpenID4VP)";

    public static final String PARAM_VP_REQUEST_ID = "vp_request_id";
    public static final String PARAM_STATUS = "status";

    public static final String PROP_PRESENTATION_DEFINITION_ID = "presentationDefinitionId";
    public static final String PROP_TIMEOUT_SECONDS = "timeout";
    public static final String CLIENT_ID_SCHEME_X509_HASH = "x509_hash";
    public static final String RESPONSE_MODE_DIRECT_POST = "direct_post";
    public static final String RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt";

    public static final String REQUEST_URI_ENDPOINT = "/openid4vp/v1/request/";
    public static final String RESPONSE_URI_ENDPOINT = "/openid4vp/v1/response";
    public static final String RESPONSE_STATUS = "status";
    public static final String RESPONSE_REQUEST_ID = "requestId";
    public static final String RESPONSE_ERROR = "error";
    public static final String RESPONSE_ERROR_DESCRIPTION = "error_description";
    public static final String RESPONSE_STATUS_SUCCESS = "success";
    public static final String RESPONSE_MESSAGE = "message";
    public static final String RESPONSE_CONTENT_TYPE_CHARSET_UTF_8 = ";charset=UTF-8";
    public static final String RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    public static final String RESPONSE_HEADER_VALUE_NOSNIFF = "nosniff";

    public static final String CLAIM_PRESENTATION_DEFINITION = "presentation_definition";
    public static final String CLAIM_CLIENT_METADATA = "client_metadata";
    public static final String METADATA_CLIENT_NAME = "client_name";
    public static final String METADATA_VP_FORMATS = "vp_formats";
    public static final String FORMAT_VC_SD_JWT = "vc+sd-jwt";
    public static final String METADATA_SD_JWT_ALG_VALUES = "sd-jwt_alg_values";
    public static final String METADATA_KB_JWT_ALG_VALUES = "kb-jwt_alg_values";
    public static final String JOSE_TYPE_OAUTH_AUTHZ_REQ = "oauth-authz-req+jwt";
    public static final String ALG_RS256 = "RS256";

    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_FAILED = "failed";

    public static final int DISPLAY_ORDER_1 = 1;
    public static final int DISPLAY_ORDER_3 = 3;

    // Configuration property display labels and descriptions
    public static final String PROP_PRESENTATION_DEFINITION_ID_DISPLAY = "Presentation Definition ID";
    public static final String PROP_PRESENTATION_DEFINITION_ID_DESC =
            "ID of the presentation definition to use for VP requests";
    public static final String PROP_TIMEOUT_SECONDS_DISPLAY = "Timeout (seconds)";
    public static final String PROP_TIMEOUT_SECONDS_DESC = "Timeout for VP requests in seconds";
    public static final String PROP_TIMEOUT_DEFAULT_VALUE = "120";
    public static final int PROP_TIMEOUT_MAX_SECONDS = 180;

    // Internal context property keys
    public static final String CONTEXT_AMR_OPENID4VP = "openid4vp";

    // Registration executor constants
    public static final String EXECUTOR_NAME = "VPRegistrationExecutor";
    public static final String CONTEXT_VP_REQUEST_ID = "vp_request_id";
    public static final String CONTEXT_WALLET_URL = "walletUrl";

    private Constants() { }
}
