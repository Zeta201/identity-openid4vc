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

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.response.CredentialIssuerMetadataResponse;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Unit tests for {@link CredentialIssuerMetadataWellKnownServlet} and
 * {@link JwtVcIssuerMetadataWellKnownServlet}.
 */
public class MetadataWellKnownServletTest {

    private static final String ISSUER_URL = "https://localhost:9443/oid4vci";
    private static final String ISSUER_METADATA_JSON = "{\"credential_issuer\":\"" + ISSUER_URL + "\"}";
    private static final String JWT_VC_METADATA_JSON = "{\"issuer\":\"" + ISSUER_URL + "\"}";

    @Test
    public void testServeCredentialIssuerMetadataForSuperTenantPath() throws Exception {

        AtomicReference<String> tenantDomainRef = new AtomicReference<>();
        AbstractMetadataWellKnownServlet servlet = credentialIssuerServlet(processor(
                tenantDomain -> {
                    tenantDomainRef.set(tenantDomain);
                    return response("credential_issuer", ISSUER_URL);
                },
                notCalled()));
        ResponseCapture capture = new ResponseCapture();

        servlet.doGet(request("/oid4vci"), capture.getResponse());

        Assert.assertEquals(tenantDomainRef.get(), MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(capture.getStatus(), HttpServletResponse.SC_OK);
        Assert.assertEquals(capture.getContentType(), "application/json");
        Assert.assertEquals(capture.getBody(), ISSUER_METADATA_JSON);
    }

    @Test
    public void testServeCredentialIssuerMetadataForTenantPath() throws Exception {

        AtomicReference<String> tenantDomainRef = new AtomicReference<>();
        AbstractMetadataWellKnownServlet servlet = credentialIssuerServlet(processor(
                tenantDomain -> {
                    tenantDomainRef.set(tenantDomain);
                    return response("credential_issuer", ISSUER_URL);
                },
                notCalled()));
        ResponseCapture capture = new ResponseCapture();

        servlet.doGet(request("/t/foo.com/oid4vci"), capture.getResponse());

        Assert.assertEquals(tenantDomainRef.get(), "foo.com");
        Assert.assertEquals(capture.getStatus(), HttpServletResponse.SC_OK);
        Assert.assertEquals(capture.getBody(), ISSUER_METADATA_JSON);
    }

    @Test
    public void testServeJwtVcIssuerMetadata() throws Exception {

        AtomicReference<String> tenantDomainRef = new AtomicReference<>();
        AbstractMetadataWellKnownServlet servlet = jwtVcIssuerServlet(processor(
                notCalled(),
                tenantDomain -> {
                    tenantDomainRef.set(tenantDomain);
                    return response("issuer", ISSUER_URL);
                }));
        ResponseCapture capture = new ResponseCapture();

        servlet.doGet(request("/oid4vci"), capture.getResponse());

        Assert.assertEquals(tenantDomainRef.get(), MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(capture.getStatus(), HttpServletResponse.SC_OK);
        Assert.assertEquals(capture.getContentType(), "application/json");
        Assert.assertEquals(capture.getBody(), JWT_VC_METADATA_JSON);
    }

    @Test
    public void testServeJwtVcIssuerMetadataForTenantPath() throws Exception {

        AtomicReference<String> tenantDomainRef = new AtomicReference<>();
        AbstractMetadataWellKnownServlet servlet = jwtVcIssuerServlet(processor(
                notCalled(),
                tenantDomain -> {
                    tenantDomainRef.set(tenantDomain);
                    return response("issuer", ISSUER_URL);
                }));
        ResponseCapture capture = new ResponseCapture();

        servlet.doGet(request("/t/foo.com/oid4vci"), capture.getResponse());

        Assert.assertEquals(tenantDomainRef.get(), "foo.com");
        Assert.assertEquals(capture.getStatus(), HttpServletResponse.SC_OK);
    }

    @Test(dataProvider = "invalidPaths")
    public void testReturnNotFoundForInvalidPath(String pathInfo) throws Exception {

        AbstractMetadataWellKnownServlet servlet = credentialIssuerServlet(processor(notCalled(), notCalled()));
        ResponseCapture capture = new ResponseCapture();

        servlet.doGet(request(pathInfo), capture.getResponse());

        Assert.assertEquals(capture.getStatus(), HttpServletResponse.SC_NOT_FOUND);
        Assert.assertTrue(capture.getBody().isEmpty());
    }

    @org.testng.annotations.DataProvider(name = "invalidPaths")
    public Object[][] invalidPaths() {

        return new Object[][]{
                {"/oid4vci/extra"},     // trailing segment beyond the issuer context
                {"/other"},             // unknown context
                {"/t/foo.com"},         // tenant without the issuer context
                {"/"},                  // no context at all
                {null},                 // servlet mapped without path info
        };
    }

    @Test
    public void testReturnJsonErrorWhenProcessorFails() throws Exception {

        AbstractMetadataWellKnownServlet servlet = credentialIssuerServlet(processor(
                tenantDomain -> {
                    throw new CredentialIssuerMetadataException("internal detail that must not leak");
                },
                notCalled()));
        ResponseCapture capture = new ResponseCapture();

        servlet.doGet(request("/oid4vci"), capture.getResponse());

        Assert.assertEquals(capture.getStatus(), HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        Assert.assertEquals(capture.getContentType(), "application/json");
        Assert.assertEquals(capture.getBody(),
                "{\"error\":\"server_error\",\"error_description\":"
                        + "\"Error while resolving OpenID4VCI credential issuer metadata.\"}");
        Assert.assertFalse(capture.getBody().contains("internal detail that must not leak"),
                "The failure detail should be logged, not returned on an unauthenticated endpoint.");
    }

    // --- helpers -------------------------------------------------------------------------------

    @FunctionalInterface
    private interface MetadataSupplier {

        CredentialIssuerMetadataResponse get(String tenantDomain) throws CredentialIssuerMetadataException;
    }

    private static MetadataSupplier notCalled() {

        return tenantDomain -> {
            throw new AssertionError("This metadata document should not have been resolved.");
        };
    }

    private static CredentialIssuerMetadataResponse response(String key, String value) {

        // A single entry is enough to assert the servlet writes exactly what the processor returned.
        return new CredentialIssuerMetadataResponse(Collections.singletonMap(key, value));
    }

    private static CredentialIssuerMetadataProcessor processor(MetadataSupplier issuerMetadata,
                                                               MetadataSupplier jwtVcIssuerMetadata) {

        return new CredentialIssuerMetadataProcessor() {
            @Override
            public CredentialIssuerMetadataResponse getMetadataResponse(String tenantDomain)
                    throws CredentialIssuerMetadataException {

                return issuerMetadata.get(tenantDomain);
            }

            @Override
            public CredentialIssuerMetadataResponse getJwtVcIssuerMetadata(String tenantDomain)
                    throws CredentialIssuerMetadataException {

                return jwtVcIssuerMetadata.get(tenantDomain);
            }
        };
    }

    private static AbstractMetadataWellKnownServlet credentialIssuerServlet(CredentialIssuerMetadataProcessor p) {

        return new CredentialIssuerMetadataWellKnownServlet() {
            @Override
            protected CredentialIssuerMetadataProcessor getCredentialIssuerMetadataProcessor() {

                return p;
            }
        };
    }

    private static AbstractMetadataWellKnownServlet jwtVcIssuerServlet(CredentialIssuerMetadataProcessor p) {

        return new JwtVcIssuerMetadataWellKnownServlet() {
            @Override
            protected CredentialIssuerMetadataProcessor getCredentialIssuerMetadataProcessor() {

                return p;
            }
        };
    }

    private static HttpServletRequest request(String pathInfo) {

        return (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> "getPathInfo".equals(method.getName())
                        ? pathInfo
                        : defaultValue(method.getReturnType()));
    }

    private static Object defaultValue(Class<?> returnType) {

        if (!returnType.isPrimitive()) {
            return null;
        }
        if (boolean.class.equals(returnType)) {
            return false;
        }
        if (char.class.equals(returnType)) {
            return '\0';
        }
        if (byte.class.equals(returnType)) {
            return (byte) 0;
        }
        if (short.class.equals(returnType)) {
            return (short) 0;
        }
        if (int.class.equals(returnType)) {
            return 0;
        }
        if (long.class.equals(returnType)) {
            return 0L;
        }
        if (float.class.equals(returnType)) {
            return 0F;
        }
        return 0D;
    }

    private static class ResponseCapture {

        private final StringWriter body = new StringWriter();
        private final PrintWriter writer = new PrintWriter(body);
        private int status = HttpServletResponse.SC_OK;
        private String contentType;

        private HttpServletResponse getResponse() {

            return (HttpServletResponse) Proxy.newProxyInstance(
                    HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "setStatus":
                                status = (Integer) args[0];
                                return null;
                            case "getStatus":
                                return status;
                            case "setContentType":
                                contentType = (String) args[0];
                                return null;
                            case "getContentType":
                                return contentType;
                            case "getWriter":
                                return writer;
                            default:
                                return defaultValue(method.getReturnType());
                        }
                    });
        }

        private int getStatus() {

            return status;
        }

        private String getContentType() {

            return contentType;
        }

        private String getBody() {

            writer.flush();
            return body.toString();
        }
    }
}
