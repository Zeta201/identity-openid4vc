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

package org.wso2.carbon.identity.openid4vc.presentation.common.constant;

/**
 * Constants for OpenID4VP (OpenID for Verifiable Presentations) implementation.
 */
public class OpenID4VPConstants {

    private OpenID4VPConstants() {

        // Prevent instantiation
    }

    /**
     * OpenID4VP Protocol constants.
     */
    public static class Protocol {

        public static final String RESPONSE_TYPE_VP_TOKEN = "vp_token";
        public static final String RESPONSE_MODE_DIRECT_POST = "direct_post";
        public static final String OPENID4VP_SCHEME = "openid4vp://";
        public static final String PRESENTATION_DEFINITION = "presentation_definition";
        /** SIOPv2 audience — fixed by the spec; wallets validate aud == this value. */
        public static final String REQUEST_AUDIENCE = "https://self-issued.me/v2";
    }

    /**
     * Request parameter constants.
     */
    public static class RequestParams {

        public static final String CLIENT_ID = "client_id";
        public static final String RESPONSE_TYPE = "response_type";
        public static final String RESPONSE_MODE = "response_mode";
        public static final String RESPONSE_URI = "response_uri";
        public static final String NONCE = "nonce";
        public static final String STATE = "state";
        public static final String REQUEST_URI = "request_uri";

        private RequestParams() {

        }
    }

    /**
     * Response parameter constants.
     */
    public static class ResponseParams {

        public static final String RESPONSE = "response";
        public static final String VP_TOKEN = "vp_token";
        public static final String ERROR = "error";
        public static final String ERROR_DESCRIPTION = "error_description";
        public static final String STATE = "state";

        private ResponseParams() {

        }
    }

    /**
     * Error codes as defined in OpenID4VP specification.
     */
    public static class ErrorCodes {
        
        // OAuth 2.0 Error Codes
        public static final String INVALID_REQUEST = "invalid_request";
        public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
        public static final String ACCESS_DENIED = "access_denied";
        public static final String SERVER_ERROR = "server_error";

        // OpenID4VP Specific Error Codes
        public static final String VP_FORMATS_NOT_SUPPORTED = "vp_formats_not_supported";

        // Wallet Error Codes
        public static final String USER_CANCELLED = "user_cancelled";
        public static final String CREDENTIAL_NOT_AVAILABLE = "credential_not_available";

        private ErrorCodes() {

        }
    }

    /**
     * Verifiable Credential format constants.
     */
    public static class VCFormats {

        public static final String JWT_VP = "jwt_vp";
        public static final String JWT_VP_JSON = "jwt_vp_json";
        public static final String JWT_VC_JSON = "jwt_vc_json";
        public static final String LDP_VP = "ldp_vp";
        public static final String LDP_VC = "ldp_vc";
        public static final String VC_SD_JWT = "vc+sd-jwt";
        public static final String DC_SD_JWT = "dc+sd-jwt";
        public static final String MSO_MDOC = "mso_mdoc";

        private VCFormats() {

        }
    }

    /**
     * HTTP and API constants.
     */
    public static class HTTP {
        
        public static final String CONTENT_TYPE_JSON = "application/json";
        public static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded";
        public static final String CONTENT_TYPE_OAUTH_AUTHZ_REQ = "application/oauth-authz-req+jwt";
        public static final String CONTENT_TYPE_TEXT_PLAIN = "text/plain";
        public static final String METHOD_GET = "GET";

        private HTTP() {

        }
    }

    /**
     * JWT claim name constants.
     */
    public static class JWTClaims {

        public static final String ISS = "iss";
        public static final String SUB = "sub";
        public static final String IAT = "iat";
        public static final String EXP = "exp";
        public static final String JTI = "jti";
        public static final String NBF = "nbf";
        public static final String AUD = "aud";
        public static final String KID = "kid";
        public static final String NONCE = "nonce";
        public static final String CNF = "cnf";
        public static final String JWK = "jwk";
        public static final String JKT = "jkt";
        public static final String VCT = "vct";
        public static final String CLIENT_ID_SCHEME = "client_id_scheme";
        public static final String DCQL_QUERY = "dcql_query";
        public static final String STATUS = "status";
        public static final String STATUS_LIST = "status_list";
        public static final String URI = "uri";
        public static final String IDX = "idx";
        public static final String BITS = "bits";
        public static final String LST = "lst";

        private JWTClaims() {

        }
    }

    /**
     * Cryptographic algorithm name constants.
     */
    public static class Algorithms {
        public static final String EDDSA = "EdDSA";
        public static final String ED25519 = "Ed25519";
        public static final String ED448 = "Ed448";
        public static final String ES256 = "ES256";
        public static final String RS256 = "RS256";
        public static final String SHA_256 = "SHA-256";
        public static final String ECDH_ES = "ECDH-ES";
        public static final String A256GCM = "A256GCM";

        private Algorithms() {

        }
    }

    /**
     * API endpoint paths.
     */
    public static class Endpoints {

        public static final String VP_RESPONSE = "/response";
        public static final String REQUEST_URI = "/request-uri";
        public static final String STATUS = "status";
        public static final String OPENID4VP_V1_PATH = "openid4vp/v1";
        public static final String TENANT_PATH_PREFIX = "t/";

        private Endpoints() {

        }
    }

    /**
     * Configuration property keys.
     */
    public static class ConfigKeys {

        public static final String FEATURE_ENABLED = "OpenID4VP.Enabled";
        public static final String BASE_URL = "OpenID4VP.BaseUrl";

        private ConfigKeys() {

        }
    }

    /**
     * JWT VC issuer metadata field name constants.
     */
    public static class IssuerMetadata {

        public static final String ISSUER = "issuer";
        public static final String JWKS_URI = "jwks_uri";

        private IssuerMetadata() {

        }
    }

    /**
     * DCQL (Digital Credentials Query Language) field name constants.
     */
    public static class DCQL {

        public static final String CREDENTIALS = "credentials";
        public static final String CREDENTIAL_SETS = "credential_sets";
        public static final String CLAIM_SETS = "claim_sets";
        public static final String ID = "id";
        public static final String FORMAT = "format";
        public static final String META = "meta";
        public static final String VCT_VALUES = "vct_values";
        public static final String CLAIMS = "claims";
        public static final String PATH = "path";
        public static final String VALUES = "values";
        public static final String OPTIONS = "options";
        public static final String REQUIRED = "required";

        public static final String TRUSTED_AUTHORITIES = "trusted_authorities";

        public static final String TRUSTED_AUTHORITY_TYPE = "type";

        public static final String TRUSTED_AUTHORITY_TYPE_AKI = "aki";

        public static final String TRUSTED_AUTHORITY_VALUES = "values";

        private DCQL() {

        }
    }

    /**
     * Client metadata field name constants.
     */
    public static class ClientMetadata {

        public static final String JWKS = "jwks";
        public static final String KEYS = "keys";
        public static final String AUTHORIZATION_ENCRYPTED_RESPONSE_ALG = "authorization_encrypted_response_alg";
        public static final String AUTHORIZATION_ENCRYPTED_RESPONSE_ENC = "authorization_encrypted_response_enc";
        
        private ClientMetadata() {

        }
    }
    
    /**
     * Default configuration values for OpenID4VP.
     */
    public static class Defaults {

        public static final String CLIENT_ID_SCHEME = "x509_san_dns";
        public static final String RESPONSE_MODE = "direct_post";
        public static final String KEY_RESOLUTION_METHOD = "X5C";

        private Defaults() {

        }
    }
}
