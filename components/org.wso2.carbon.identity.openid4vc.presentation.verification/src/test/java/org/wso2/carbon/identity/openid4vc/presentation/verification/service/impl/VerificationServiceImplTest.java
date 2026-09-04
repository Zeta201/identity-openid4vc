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

package org.wso2.carbon.identity.openid4vc.presentation.verification.service.impl;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.common.constant.VPConstants;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.DcqlQuery;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationMetadata;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.CredentialVerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.dto.PresentationVerificationResult;
import org.wso2.carbon.identity.openid4vc.presentation.verification.handlers.Verifier;
import org.wso2.carbon.identity.openid4vc.presentation.verification.util.VerificationConstants;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link VerificationServiceImpl}.
 * Tests credential verification logic, claim constraint evaluation, and error conditions.
 */
public class VerificationServiceImplTest {

    private static final int TENANT_ID = 1;
    private static final String DCQL_FORMAT = Constants.VC_SD_JWT_FORMAT;
    private static final String CRED_ID = "cred_1_1";

    @Mock
    private Verifier mockVerifier;

    private VerificationServiceImpl service;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        service = new VerificationServiceImpl();
    }

    @Test(priority = 1, description = "Test that verify returns a not-verified result when credential tokens are null")
    public void testVerifyWithNullTokensReturnsNotVerified() throws Exception {

        // Execute test
        PresentationVerificationResult result = service.verify(emptyQuery(), TENANT_ID, null, null, null);

        // Verify
        Assert.assertFalse(result.isVerified(),
                "Result should not be verified when credential tokens are null");
        Assert.assertEquals(result.getStatusMessage(), VerificationConstants.STATUS_VERIFICATION_FAILED,
                "Status message should indicate verification failure");
    }

    @Test(priority = 2,
            description = "Test verify returns not-verified with errors when credential tokens map is empty")
    public void testVerifyWithEmptyTokensReturnsNotVerified() throws Exception {

        // Execute test
        PresentationVerificationResult result = service.verify(emptyQuery(), TENANT_ID, Collections.emptyMap(), null, null);

        // Verify
        Assert.assertFalse(result.isVerified(),
                "Result should not be verified when credential tokens map is empty");
        Assert.assertFalse(result.getErrors().isEmpty(),
                "Errors list should not be empty when credential tokens map is empty");
    }

    @Test(priority = 3,
            description = "Test that verify returns a not-verified result with errors when the definition is null")
    public void testVerifyWithNullDefinitionReturnsNotVerified() throws Exception {

        // Execute test
        PresentationVerificationResult result = service.verify(null, TENANT_ID, Map.of(CRED_ID, "token"), null, null);

        // Verify
        Assert.assertFalse(result.isVerified(),
                "Result should not be verified when the definition is null");
        Assert.assertFalse(result.getErrors().isEmpty(),
                "Errors list should not be empty when the definition is null");
    }

    @Test(priority = 4,
            description = "Test verify returns not-verified when the token map lacks the requested credential")
    public void testVerifyWhenCredentialIdNotInTokenMapReturnsNotVerified() throws Exception {

        // Set up a query requesting CRED_ID but only provide an unknown credential
        PresentationVerificationResult result = service.verify(queryForCredential(CRED_ID), TENANT_ID,
                Map.of("unknown_cred", "token"), null, null);

        // Verify
        Assert.assertFalse(result.isVerified(),
                "Result should not be verified when the credential ID is not in the token map");
        Assert.assertTrue(result.getErrors().get(0).contains("does not contain the requested credential"),
                "Error message should mention the missing credential");
    }

    @Test(priority = 5,
            description = "Test verify returns a verified result when a mandatory claim is present")
    public void testVerifyWithMandatoryClaimPresentReturnsVerified() throws Exception {

        // Set up a credential containing the mandatory claim
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "alice@example.com");
        injectMockVerifier(claims);

        DcqlQuery.ClaimQuery constraint = new DcqlQuery.ClaimQuery("email", true);

        // Execute test
        PresentationVerificationResult result = service.verify(queryWithClaims(constraint),
                TENANT_ID, Map.of(CRED_ID, "token"), null, null);

        // Verify
        Assert.assertTrue(result.isVerified(),
                "Result should be verified when a mandatory claim is present");
    }

    @Test(priority = 6,
            description = "Test verify returns not-verified with a descriptive error when a mandatory claim is absent")
    public void testVerifyWithMandatoryClaimMissingReturnsNotVerified() throws Exception {

        // Set up a credential that is missing the mandatory claim
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "Alice");
        injectMockVerifier(claims);

        DcqlQuery.ClaimQuery constraint = new DcqlQuery.ClaimQuery("email", true);

        // Execute test
        PresentationVerificationResult result = service.verify(queryWithClaims(constraint),
                TENANT_ID, Map.of(CRED_ID, "token"), null, null);

        // Verify
        Assert.assertFalse(result.isVerified(),
                "Result should not be verified when a mandatory claim is missing");
        String error = result.getErrors().get(0);
        Assert.assertTrue(error.contains("email") && error.contains("is missing"),
                "Error message should mention the missing claim name");
    }

    @Test(priority = 7,
            description = "Test verify returns a verified result when an optional claim is absent")
    public void testVerifyWithOptionalClaimMissingReturnsVerified() throws Exception {

        // Set up an optional claim that is not present in the credential
        injectMockVerifier(new HashMap<>());

        DcqlQuery.ClaimQuery constraint = new DcqlQuery.ClaimQuery("phone", false);

        // Execute test
        PresentationVerificationResult result = service.verify(queryWithClaims(constraint),
                TENANT_ID, Map.of(CRED_ID, "token"), null, null);

        // Verify
        Assert.assertTrue(result.isVerified(),
                "Result should still be verified when only optional claims are missing");
    }

    @Test(priority = 10,
            description = "Test a successful verification result is marked verified with the success status message")
    public void testVerifySuccessResultIsVerifiedWithSuccessMessage() throws Exception {

        // Set up a credential with a name claim
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "Alice");
        injectMockVerifier(claims);

        // Execute test
        PresentationVerificationResult result = service.verify(queryForCredential(CRED_ID), TENANT_ID,
                Map.of(CRED_ID, "token"), null, null);

        // Verify
        Assert.assertTrue(result.isVerified(),
                "Result should be verified on successful verification");
        Assert.assertEquals(result.getStatusMessage(), VerificationConstants.STATUS_VERIFICATION_SUCCESS,
                "Status message should indicate success");
        Assert.assertTrue(result.getErrors().isEmpty(),
                "Errors list should be empty on successful verification");
    }

    @Test(priority = 11,
            description = "Test that a successful verification result includes all credential claims in verifiedClaims")
    public void testVerifySuccessVerifiedClaimsIncludesAllClaims() throws Exception {

        // Set up a credential with multiple claims
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "alice@example.com");
        claims.put("name", "Alice");
        injectMockVerifier(claims);

        // Execute test
        PresentationVerificationResult result = service.verify(queryForCredential(CRED_ID), TENANT_ID,
                Map.of(CRED_ID, "token"), null, null);

        // Verify all claims are in the result
        Assert.assertTrue(result.isVerified(),
                "Result should be verified");
        Assert.assertTrue(result.getVerifiedClaims().containsKey("email"),
                "verifiedClaims should contain the 'email' claim");
        Assert.assertTrue(result.getVerifiedClaims().containsKey("name"),
                "verifiedClaims should contain the 'name' claim");
    }

    @Test(priority = 12,
            description = "Test that a successful verification result contains the issuer in the credential metadata")
    public void testVerifySuccessMetadataContainsIssuer() throws Exception {

        // Set up a credential with an iss claim
        Map<String, Object> claims = new HashMap<>();
        claims.put(VPConstants.JWTClaims.ISS, "https://issuer.example.com");
        injectMockVerifier(claims);

        // Execute test
        PresentationVerificationResult result = service.verify(queryForCredential(CRED_ID), TENANT_ID,
                Map.of(CRED_ID, "token"), null, null);

        // Verify issuer is present in metadata
        Assert.assertTrue(result.isVerified(),
                "Result should be verified");
        Assert.assertFalse(result.getCredentialMetadataList().isEmpty(),
                "Credential metadata list should not be empty");
        PresentationMetadata metadata = result.getCredentialMetadataList().get(0);
        Assert.assertEquals(metadata.getIssuer(), "https://issuer.example.com",
                "Metadata issuer should match the iss claim in the credential");
    }

    private DcqlQuery emptyQuery() {

        return new DcqlQuery.Builder().build();
    }

    private DcqlQuery queryForCredential(String credentialId) {

        DcqlQuery.CredentialQuery cq = new DcqlQuery.CredentialQuery.Builder()
                .id(credentialId)
                .format(DCQL_FORMAT)
                .build();
        return new DcqlQuery.Builder().credentials(Collections.singletonList(cq)).build();
    }

    private DcqlQuery queryWithClaims(DcqlQuery.ClaimQuery... claimQueries) {

        DcqlQuery.CredentialQuery cq = new DcqlQuery.CredentialQuery.Builder()
                .id(CRED_ID)
                .format(DCQL_FORMAT)
                .claims(Arrays.asList(claimQueries))
                .build();
        return new DcqlQuery.Builder().credentials(Collections.singletonList(cq)).build();
    }

    private void injectMockVerifier(Map<String, Object> returnedClaims) throws Exception {

        PresentationMetadata metadata = new PresentationMetadata.Builder()
                .issuer((String) returnedClaims.get(VPConstants.JWTClaims.ISS))
                .build();
        CredentialVerificationResult output = new CredentialVerificationResult(metadata, returnedClaims);
        when(mockVerifier.getFormat()).thenReturn(DCQL_FORMAT);
        when(mockVerifier.verify(any())).thenReturn(output);
        Field f = VerificationServiceImpl.class.getDeclaredField("verifiers");
        f.setAccessible(true);
        f.set(service, Collections.singletonList(mockVerifier));
    }
}
