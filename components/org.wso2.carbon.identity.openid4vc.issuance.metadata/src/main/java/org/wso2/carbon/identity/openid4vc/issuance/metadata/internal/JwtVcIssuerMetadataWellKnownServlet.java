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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.issuance.metadata.internal;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.response.CredentialIssuerMetadataResponse;

import javax.servlet.Servlet;

/**
 * Serves the JWT VC issuer metadata at the well-known URI required by draft-ietf-oauth-sd-jwt-vc,
 * i.e. {@code /.well-known/jwt-vc-issuer/oid4vci}.
 */
@Component(
        service = Servlet.class,
        immediate = true,
        property = {
                "osgi.http.whiteboard.servlet.pattern=/.well-known/jwt-vc-issuer/*",
                "osgi.http.whiteboard.servlet.name=OID4VCIJwtVcIssuerMetadata",
                "osgi.http.whiteboard.servlet.asyncSupported=true"
        }
)
public class JwtVcIssuerMetadataWellKnownServlet extends AbstractMetadataWellKnownServlet {

    private static final long serialVersionUID = 4620470195274150183L;

    @Override
    protected CredentialIssuerMetadataResponse resolveMetadata(CredentialIssuerMetadataProcessor processor,
                                                               String tenantDomain)
            throws CredentialIssuerMetadataException {

        return processor.getJwtVcIssuerMetadata(tenantDomain);
    }

    @Override
    protected String getMetadataTypeName() {

        return "JWT VC issuer metadata";
    }
}
