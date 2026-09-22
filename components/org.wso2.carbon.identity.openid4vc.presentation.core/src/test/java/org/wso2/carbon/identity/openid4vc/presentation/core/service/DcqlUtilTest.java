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

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.service.util.DcqlUtil;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.Issuer;
import org.wso2.carbon.identity.openid4vc.template.management.model.KeyResolutionMethod;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationClaim;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for {@link DcqlUtil}.
 */
@SuppressWarnings("unchecked")
public class DcqlUtilTest {

    @Test(priority = 1, description = "Test buildDcqlQuery with null definition returns empty credentials list")
    public void testBuildDcqlQueryNullDefinition() {

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(null);

        Assert.assertNotNull(result, "Result should not be null");
        List<?> credentials = (List<?>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertNotNull(credentials, "Credentials list should not be null");
        Assert.assertTrue(credentials.isEmpty(), "Credentials should be empty for null definition");
        Assert.assertNull(result.get(Constants.DCQL.CREDENTIAL_SETS),
                "credential_sets should be absent when there are no credentials");
    }

    @Test(priority = 2, description = "Test buildDcqlQuery with no credentials returns empty list")
    public void testBuildDcqlQueryEmptyCredentials() {

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-1")
                .credentials(Collections.emptyList())
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);

        List<?> credentials = (List<?>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertTrue(credentials.isEmpty(), "Credentials list should be empty");
    }

    @Test(priority = 3, description = "Test buildDcqlQuery sets id, format, and meta for a single credential")
    public void testBuildDcqlQueryCredentialBasicFields() {

        Credential cred = new Credential();
        cred.setIdentifier("employee_badge");
        cred.setFormat(Constants.VC_SD_JWT_FORMAT);
        cred.setType("EmployeeBadgeCredential");

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-basic")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);

        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertEquals(credentials.size(), 1, "Should have exactly one credential entry");

        Map<String, Object> credEntry = credentials.get(0);
        Assert.assertEquals(credEntry.get(Constants.DCQL.ID), "employee_badge");
        Assert.assertEquals(credEntry.get(Constants.DCQL.FORMAT), Constants.VC_SD_JWT_FORMAT);

        Map<String, Object> meta = (Map<String, Object>) credEntry.get(Constants.DCQL.META);
        Assert.assertNotNull(meta, "meta should be present when credential type is set");
        List<String> vctValues = (List<String>) meta.get(Constants.DCQL.VCT_VALUES);
        Assert.assertEquals(vctValues, Collections.singletonList("EmployeeBadgeCredential"),
                "vct_values should contain the credential type");
    }

    @Test(priority = 4, description = "Test buildDcqlQuery omits meta when credential type is blank")
    public void testBuildDcqlQueryNoMetaWhenTypeBlank() {

        Credential cred = new Credential();
        cred.setIdentifier("untyped_cred");
        cred.setFormat(Constants.VC_SD_JWT_FORMAT);

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-no-type")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);

        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        Map<String, Object> credEntry = credentials.get(0);
        Assert.assertNull(credEntry.get(Constants.DCQL.META), "meta should be absent when type is not set");
    }

    @Test(priority = 5, description = "Test buildDcqlQuery serializes claims with path and id")
    public void testBuildDcqlQueryClaims() {

        Credential cred = buildCredentialWithClaims("cred-with-claims", Constants.VC_SD_JWT_FORMAT,
                claim("given_name", true));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-claims")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        List<Map<String, Object>> claims = (List<Map<String, Object>>) credentials.get(0).get(Constants.DCQL.CLAIMS);

        Assert.assertNotNull(claims, "Claims should be present");
        Assert.assertEquals(claims.size(), 1, "Should have one claim entry");

        Map<String, Object> givenNameClaim = claims.get(0);
        Assert.assertEquals(givenNameClaim.get(Constants.DCQL.ID), "given_name");
        Assert.assertEquals(givenNameClaim.get(Constants.DCQL.PATH),
                Collections.singletonList("given_name"));
    }

    @Test(priority = 6, description = "Test buildDcqlQuery does not split a claim name containing a literal dot")
    public void testBuildDcqlQueryClaimWithDotInPath() {

        Credential cred = buildCredentialWithClaims("cred-uri-claim", Constants.VC_SD_JWT_FORMAT,
                claim("http://wso2.org/vc/claim/ibm", true));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-uri-claim")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        List<Map<String, Object>> claims = (List<Map<String, Object>>) credentials.get(0).get(Constants.DCQL.CLAIMS);

        Assert.assertEquals(claims.size(), 1, "Should have one claim entry");
        Assert.assertEquals(claims.get(0).get(Constants.DCQL.PATH),
                Collections.singletonList("http://wso2.org/vc/claim/ibm"),
                "A claim name containing a dot must remain a single path segment");
    }

    @Test(priority = 7, description = "Test buildDcqlQuery adds claim_sets when mandatory and optional claims mixed")
    public void testBuildDcqlQueryClaimSetsWhenMixedMandatory() {

        Credential cred = buildCredentialWithClaims("mixed-cred", Constants.VC_SD_JWT_FORMAT,
                claim("sub", true),
                claim("email", false));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-mixed-claims")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        List<List<String>> claimSets = (List<List<String>>) credentials.get(0).get(Constants.DCQL.CLAIM_SETS);

        Assert.assertNotNull(claimSets, "claim_sets should be present when mandatory and optional claims are mixed");
        Assert.assertEquals(claimSets.size(), 2,
                "claim_sets should contain [all-claims-set, mandatory-only-set]");
        Assert.assertTrue(claimSets.get(0).containsAll(Arrays.asList("sub", "email")),
                "First set should contain all claim ids");
        Assert.assertEquals(claimSets.get(1), Collections.singletonList("sub"),
                "Second set should contain only mandatory claim ids");
    }

    @Test(priority = 8, description = "Test buildDcqlQuery omits claim_sets when all claims are mandatory")
    public void testBuildDcqlQueryNoClaimSetsWhenAllMandatory() {

        Credential cred = buildCredentialWithClaims("all-mandatory", Constants.VC_SD_JWT_FORMAT,
                claim("sub", true), claim("email", true));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-all-mandatory")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertNull(credentials.get(0).get(Constants.DCQL.CLAIM_SETS),
                "claim_sets should be absent when all claims are mandatory");
    }

    @Test(priority = 9, description = "Test buildDcqlQuery omits claim_sets when all claims are optional")
    public void testBuildDcqlQueryNoClaimSetsWhenAllOptional() {

        Credential cred = buildCredentialWithClaims("all-optional", Constants.VC_SD_JWT_FORMAT,
                claim("email", false), claim("phone", false));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-all-optional")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertNull(credentials.get(0).get(Constants.DCQL.CLAIM_SETS),
                "claim_sets should be absent when all claims are optional");
    }

    @Test(priority = 10, description = "Test buildDcqlQuery adds credential_sets with all credential ids")
    public void testBuildDcqlQueryCredentialSets() {

        Credential cred1 = new Credential();
        cred1.setIdentifier("id_card");
        cred1.setFormat(Constants.VC_SD_JWT_FORMAT);
        Credential cred2 = new Credential();
        cred2.setIdentifier("driver_license");
        cred2.setFormat(Constants.VC_SD_JWT_FORMAT);

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-two-creds")
                .credentials(Arrays.asList(cred1, cred2))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);

        List<Map<String, Object>> credentialSets =
                (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIAL_SETS);
        Assert.assertNotNull(credentialSets, "credential_sets should be present");
        Assert.assertEquals(credentialSets.size(), 1);

        List<List<String>> options = (List<List<String>>) credentialSets.get(0).get(Constants.DCQL.OPTIONS);
        Assert.assertEquals(options.size(), 1);
        Assert.assertTrue(options.get(0).containsAll(Arrays.asList("id_card", "driver_license")),
                "options should list all credential ids");
    }

    @Test(priority = 11, description = "Test buildDcqlQuery omits trusted_authorities for non-x5c issuers")
    public void testBuildDcqlQueryNoTrustedAuthoritiesForNonX5c() {

        Issuer issuer = new Issuer();
        issuer.setKeyResolutionMethod(KeyResolutionMethod.JWKS_URI);
        issuer.setIssuerUrl("https://issuer.example.com");

        Credential cred = new Credential();
        cred.setIdentifier("cred-jwks");
        cred.setFormat(Constants.VC_SD_JWT_FORMAT);
        cred.setIssuers(Collections.singletonList(issuer));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-jwks")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertNull(credentials.get(0).get(Constants.DCQL.TRUSTED_AUTHORITIES),
                "trusted_authorities should be absent for non-x5c issuers");
    }

    @Test(priority = 12, description = "Test buildDcqlQuery omits trusted_authorities for x5c issuer with blank cert")
    public void testBuildDcqlQueryTrustedAuthoritiesBlankCert() {

        Issuer issuer = new Issuer();
        issuer.setKeyResolutionMethod(KeyResolutionMethod.X5C);
        issuer.setCertificate(null);

        Credential cred = new Credential();
        cred.setIdentifier("cred-x5c-no-cert");
        cred.setFormat(Constants.VC_SD_JWT_FORMAT);
        cred.setIssuers(Collections.singletonList(issuer));

        PresentationDefinition definition = new PresentationDefinition.Builder()
                .id("def-x5c-blank")
                .credentials(Collections.singletonList(cred))
                .build();

        Map<String, Object> result = DcqlUtil.buildDcqlQuery(definition);
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) result.get(Constants.DCQL.CREDENTIALS);
        Assert.assertNull(credentials.get(0).get(Constants.DCQL.TRUSTED_AUTHORITIES),
                "trusted_authorities should be absent when x5c issuer certificate is blank");
    }

    private static PresentationClaim claim(String path, boolean mandatory) {

        PresentationClaim c = new PresentationClaim();
        c.setPath(path);
        c.setMandatory(mandatory);
        return c;
    }

    private static Credential buildCredentialWithClaims(String identifier, String format,
            PresentationClaim... claims) {

        Credential cred = new Credential();
        cred.setIdentifier(identifier);
        cred.setFormat(format);
        cred.setClaims(Arrays.asList(claims));
        return cred;
    }
}
