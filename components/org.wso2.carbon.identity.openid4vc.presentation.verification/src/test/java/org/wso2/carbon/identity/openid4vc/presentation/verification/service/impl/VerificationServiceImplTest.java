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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationRequestDTO;
import org.wso2.carbon.identity.openid4vc.presentation.core.dto.VerificationResponseDTO;
import org.wso2.carbon.identity.openid4vc.presentation.verification.exception.VerificationException;
import org.wso2.carbon.identity.openid4vc.presentation.verification.internal.PresentationVerificationDataHolder;
import org.wso2.carbon.identity.openid4vc.presentation.verification.verifier.FormatVerifier;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationClaim;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link VerificationServiceImpl}.
 * Tests format-handler routing and claim constraint enforcement via {@code verifyPresentation}.
 */
public class VerificationServiceImplTest {

    private static final String DCQL_FORMAT = Constants.VC_SD_JWT_FORMAT;
    private static final String CRED_ID = "cred_1_1";

    @Mock
    private FormatVerifier mockFormatVerifier;

    private VerificationServiceImpl service;
    private MockedStatic<PresentationVerificationDataHolder> mockedHolder;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
        service = new VerificationServiceImpl();

        PresentationVerificationDataHolder mockHolderInstance =
                Mockito.mock(PresentationVerificationDataHolder.class);
        when(mockHolderInstance.getFormatVerifiers())
                .thenReturn(Collections.singletonList(mockFormatVerifier));
        when(mockFormatVerifier.getFormat()).thenReturn(DCQL_FORMAT);

        mockedHolder = Mockito.mockStatic(PresentationVerificationDataHolder.class);
        mockedHolder.when(PresentationVerificationDataHolder::getInstance).thenReturn(mockHolderInstance);
    }

    @AfterMethod
    public void tearDown() {

        if (mockedHolder != null) {
            mockedHolder.close();
        }
    }

    @Test(priority = 1,
            description = "No format verifier registered — should throw VerificationException",
            expectedExceptions = VerificationException.class)
    public void testNoFormatVerifierThrows() throws Exception {

        when(mockFormatVerifier.getFormat()).thenReturn("some-other-format");

        Credential credential = new Credential();
        credential.setIdentifier(CRED_ID);
        credential.setFormat(DCQL_FORMAT);

        service.verifyPresentation(new VerificationRequestDTO("token", credential, null, null));
    }

    @Test(priority = 2,
            description = "Format verifier succeeds — should return VerificationResponseDTO with the credential id")
    public void testFormatVerifierSuccessReturnsResult() throws Exception {

        VerificationResponseDTO mockResponse = new VerificationResponseDTO();
        mockResponse.setCredentialId(CRED_ID);
        mockResponse.setCredentialFormat(DCQL_FORMAT);
        mockResponse.setSubjectClaims(new HashMap<>());
        when(mockFormatVerifier.verifyCredential(any())).thenReturn(mockResponse);

        Credential credential = new Credential();
        credential.setIdentifier(CRED_ID);
        credential.setFormat(DCQL_FORMAT);

        VerificationResponseDTO result = service.verifyPresentation(
                new VerificationRequestDTO("token", credential, null, null));

        Assert.assertEquals(result.getCredentialId(), CRED_ID);
    }

    @Test(priority = 3,
            description = "Mandatory claim present in verified credential — should return successfully")
    public void testMandatoryClaimPresentReturnsResult() throws Exception {

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "alice@example.com");

        VerificationResponseDTO mockResponse = new VerificationResponseDTO();
        mockResponse.setSubjectClaims(claims);
        when(mockFormatVerifier.verifyCredential(any())).thenReturn(mockResponse);

        PresentationClaim mandatoryEmail = new PresentationClaim();
        mandatoryEmail.setPath("email");
        mandatoryEmail.setMandatory(true);

        Credential credential = new Credential();
        credential.setIdentifier(CRED_ID);
        credential.setFormat(DCQL_FORMAT);
        credential.setClaims(Collections.singletonList(mandatoryEmail));

        VerificationResponseDTO result = service.verifyPresentation(
                new VerificationRequestDTO("token", credential, null, null));

        Assert.assertNotNull(result);
    }

    @Test(priority = 4,
            description = "Mandatory claim absent from verified credential — should throw VerificationException",
            expectedExceptions = VerificationException.class)
    public void testMandatoryClaimMissingThrows() throws Exception {

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "Alice");

        VerificationResponseDTO mockResponse = new VerificationResponseDTO();
        mockResponse.setSubjectClaims(claims);
        when(mockFormatVerifier.verifyCredential(any())).thenReturn(mockResponse);

        PresentationClaim mandatoryEmail = new PresentationClaim();
        mandatoryEmail.setPath("email");
        mandatoryEmail.setMandatory(true);

        Credential credential = new Credential();
        credential.setIdentifier(CRED_ID);
        credential.setFormat(DCQL_FORMAT);
        credential.setClaims(Collections.singletonList(mandatoryEmail));

        service.verifyPresentation(new VerificationRequestDTO("token", credential, null, null));
    }

    @Test(priority = 5,
            description = "Optional claim absent from verified credential — should return successfully")
    public void testOptionalClaimMissingReturnsResult() throws Exception {

        VerificationResponseDTO mockResponse = new VerificationResponseDTO();
        mockResponse.setSubjectClaims(new HashMap<>());
        when(mockFormatVerifier.verifyCredential(any())).thenReturn(mockResponse);

        PresentationClaim optionalPhone = new PresentationClaim();
        optionalPhone.setPath("phone");
        optionalPhone.setMandatory(false);

        Credential credential = new Credential();
        credential.setIdentifier(CRED_ID);
        credential.setFormat(DCQL_FORMAT);
        credential.setClaims(Collections.singletonList(optionalPhone));

        VerificationResponseDTO result = service.verifyPresentation(
                new VerificationRequestDTO("token", credential, null, null));

        Assert.assertNotNull(result);
    }
}
