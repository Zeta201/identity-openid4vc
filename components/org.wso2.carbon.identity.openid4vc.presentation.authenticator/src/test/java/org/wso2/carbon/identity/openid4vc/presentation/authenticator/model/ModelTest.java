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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Map;

/**
 * Test class for authenticator model classes.
 * Tests builder patterns and getter/setter behaviour on model objects.
 */
public class ModelTest {

    @Test(priority = 1, description = "Test that VPAuthorizationRequest builder correctly sets all fields")
    public void testVPRequest() {

        // Build a request using the builder
        VPAuthorizationRequest request = new VPAuthorizationRequest.Builder()
                .requestId("id1")
                .nonce("nonce1")
                .clientId("client1")
                .status(VPFlowStatus.ACTIVE)
                .build();

        // Verify all fields are set correctly
        Assert.assertEquals(request.getRequestId(), "id1",
                "requestId should match the value set in the builder");
        Assert.assertEquals(request.getNonce(), "nonce1",
                "nonce should match the value set in the builder");
        Assert.assertEquals(request.getStatus(), VPFlowStatus.ACTIVE,
                "status should match the value set in the builder");
    }

    @Test(priority = 2, description = "Test that VPFlowInitiationResult correctly stores all fields")
    public void testVPFlowInitiationResult() {

        VPFlowInitiationResult result = new VPFlowInitiationResult(
                "req-2",
                "openid4vp://wallet?request_uri=https://example.com",
                "https://example.com/request/req-2", "client-1", 9999999999L);

        Assert.assertEquals(result.getRequestId(), "req-2",
                "requestId should match the value passed to the constructor");
        Assert.assertEquals(result.getClientId(), "client-1",
                "clientId should match the value passed to the constructor");
        Assert.assertEquals(result.getExpiresAt(), 9999999999L,
                "expiresAt should match the value passed to the constructor");
    }

    @Test(priority = 3, description = "Test that WalletSubmission correctly stores requestId and credential tokens")
    public void testWalletSubmission() {

        // Build a wallet submission
        WalletSubmission submission = new WalletSubmission();
        submission.setRequestId("req1");
        Map<String, String> credentialTokens = Map.of("cred1", "token~disc~kb~");
        submission.setCredentialTokens(credentialTokens);

        // Verify fields are stored correctly
        Assert.assertEquals(submission.getRequestId(), "req1",
                "requestId should match the value that was set");
        Assert.assertEquals(submission.getCredentialTokens(), credentialTokens,
                "credentialTokens should match the map that was set");
    }
}
