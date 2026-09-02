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

package org.wso2.carbon.identity.openid4vc.template.management.dao;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.openid4vc.template.management.dao.impl.PresentationDefinitionDAOImpl;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementException;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@WithH2Database(files = {"dbscripts/h2.sql"})
@WithCarbonHome
public class PresentationDefinitionDAOTest {

    private static final int TENANT_ID = -1234;
    private static final int OTHER_TENANT_ID = 9999;

    private PresentationDefinitionDAOImpl dao;

    private String definitionId;
    private static final String IDENTIFIER = "test-definition";
    private static final String DISPLAY_NAME = "Test Definition";
    private static final String DESCRIPTION = "A definition for testing";

    @BeforeClass
    public void setUp() throws Exception {

        dao = new PresentationDefinitionDAOImpl();
        definitionId = UUID.randomUUID().toString();
        dao.createPresentationDefinition(buildDefinition(definitionId, IDENTIFIER, DISPLAY_NAME));
    }

    @Test(priority = 1)
    public void testGetPresentationDefinitionByIdReturnsDefinitionForValidId() throws Exception {

        PresentationDefinition result = dao.getPresentationDefinitionById(definitionId, TENANT_ID);

        Assert.assertNotNull(result, "Definition should be found for a valid ID");
        Assert.assertEquals(result.getDefinitionId(), definitionId);
        Assert.assertEquals(result.getIdentifier(), IDENTIFIER);
        Assert.assertEquals(result.getDisplayName(), DISPLAY_NAME);
    }

    @Test(priority = 2)
    public void testGetPresentationDefinitionByIdReturnsNullForUnknownId() throws Exception {

        PresentationDefinition result = dao.getPresentationDefinitionById(
                UUID.randomUUID().toString(), TENANT_ID);

        Assert.assertNull(result, "Unknown ID should return null");
    }

    @Test(priority = 3)
    public void testGetPresentationDefinitionByIdReturnsNullForWrongTenant() throws Exception {

        PresentationDefinition result = dao.getPresentationDefinitionById(definitionId, OTHER_TENANT_ID);

        Assert.assertNull(result, "Wrong tenant should return null");
    }

    @Test(priority = 4)
    public void testGetPresentationDefinitionByIdentifierReturnsDefinition() throws Exception {

        PresentationDefinition result =
                dao.getPresentationDefinitionByIdentifier(IDENTIFIER, TENANT_ID);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getDefinitionId(), definitionId);
    }

    @Test(priority = 5)
    public void testGetPresentationDefinitionByIdentifierReturnsNullForUnknownIdentifier()
            throws Exception {

        PresentationDefinition result =
                dao.getPresentationDefinitionByIdentifier("nonexistent", TENANT_ID);

        Assert.assertNull(result);
    }

    @Test(priority = 6)
    public void testGetAllPresentationDefinitionsReturnsList() throws Exception {

        List<PresentationDefinition> all = dao.getAllPresentationDefinitions(TENANT_ID);

        Assert.assertNotNull(all);
        Assert.assertFalse(all.isEmpty(), "Should have at least one definition");
        boolean found = all.stream().anyMatch(d -> definitionId.equals(d.getDefinitionId()));
        Assert.assertTrue(found, "Created definition should appear in the full list");
    }

    @Test(priority = 7)
    public void testGetAllPresentationDefinitionsReturnsEmptyForOtherTenant() throws Exception {

        List<PresentationDefinition> all = dao.getAllPresentationDefinitions(OTHER_TENANT_ID);

        Assert.assertNotNull(all);
        Assert.assertTrue(all.isEmpty(), "Other tenant should have no definitions");
    }

    @Test(priority = 8)
    public void testPresentationDefinitionExistsReturnsTrueForKnownId() throws Exception {

        Assert.assertTrue(dao.presentationDefinitionExists(definitionId, TENANT_ID));
    }

    @Test(priority = 9)
    public void testPresentationDefinitionExistsReturnsFalseForUnknownId() throws Exception {

        Assert.assertFalse(dao.presentationDefinitionExists(UUID.randomUUID().toString(), TENANT_ID));
    }

    @Test(priority = 10)
    public void testPresentationDefinitionIdentifierExistsReturnsTrueForKnownIdentifier()
            throws Exception {

        Assert.assertTrue(dao.presentationDefinitionIdentifierExists(IDENTIFIER, TENANT_ID));
    }

    @Test(priority = 11)
    public void testPresentationDefinitionIdentifierExistsReturnsFalseForUnknownIdentifier()
            throws Exception {

        Assert.assertFalse(
                dao.presentationDefinitionIdentifierExists("nonexistent-slug", TENANT_ID));
    }

    @Test(priority = 12)
    public void testUpdatePresentationDefinitionPersistsChanges() throws Exception {

        PresentationDefinition update = buildDefinition(definitionId, IDENTIFIER, "Updated Name");

        dao.updatePresentationDefinition(update, Collections.emptyList(), TENANT_ID);

        PresentationDefinition reloaded =
                dao.getPresentationDefinitionById(definitionId, TENANT_ID);
        Assert.assertEquals(reloaded.getDisplayName(), "Updated Name",
                "Display name should reflect the update");
    }

    @Test(priority = 13)
    public void testCreateWithCredentialAndReadBack() throws Exception {

        String id = UUID.randomUUID().toString();
        PresentationDefinition def = buildDefinition(id, "with-creds", "With Credentials");

        PresentationDefinition.RequestedCredential cred = new PresentationDefinition.RequestedCredential();
        cred.setIdentifier("cred-1");
        cred.setType("VerifiableId");
        cred.setFormat("vc+sd-jwt");

        PresentationDefinition.ClaimConstraint claim = new PresentationDefinition.ClaimConstraint();
        claim.setPath("given_name");
        cred.setClaims(Collections.singletonList(claim));
        def.setRequestedCredentials(Collections.singletonList(cred));

        dao.createPresentationDefinition(def);

        PresentationDefinition loaded = dao.getPresentationDefinitionById(id, TENANT_ID);
        Assert.assertNotNull(loaded);
        Assert.assertNotNull(loaded.getRequestedCredentials());
        Assert.assertEquals(loaded.getRequestedCredentials().size(), 1);
        Assert.assertEquals(loaded.getRequestedCredentials().get(0).getIdentifier(), "cred-1");
    }

    @Test(priority = 14)
    public void testCreateDuplicateIdentifierThrowsClientException() {

        PresentationDefinition duplicate =
                buildDefinition(UUID.randomUUID().toString(), IDENTIFIER, "Duplicate");
        try {
            dao.createPresentationDefinition(duplicate);
            Assert.fail("Expected PresentationManagementClientException for duplicate identifier");
        } catch (PresentationManagementClientException e) {
            // expected
        } catch (PresentationManagementException e) {
            Assert.fail("Expected client exception, got server exception: " + e.getMessage());
        }
    }

    @Test(priority = 15)
    public void testListReturnsPaginatedResults() throws Exception {

        List<PresentationDefinition> page =
                dao.list(10, TENANT_ID, "ASC", new ArrayList<>());

        Assert.assertNotNull(page);
        Assert.assertFalse(page.isEmpty());
    }

    @Test(priority = 16)
    public void testGetDefinitionsCountReturnsNonZero() throws Exception {

        Integer count = dao.getDefinitionsCount(TENANT_ID, new ArrayList<>());

        Assert.assertNotNull(count);
        Assert.assertTrue(count > 0, "Count should be positive for a tenant with definitions");
    }

    @Test(priority = 17)
    public void testIsDefinitionInUseReturnsFalseWhenNoConnections() throws Exception {

        Assert.assertFalse(dao.isDefinitionInUse(definitionId, TENANT_ID),
                "Definition should not be in use when no authenticator references it");
    }

    @Test(priority = 18)
    public void testGetConnectedIdpsReturnsEmptyWhenNoneLinked() throws Exception {

        Assert.assertTrue(dao.getConnectedIdps(definitionId, TENANT_ID).isEmpty());
    }

    @Test(priority = 19)
    public void testDeletePresentationDefinitionRemovesIt() throws Exception {

        String id = UUID.randomUUID().toString();
        dao.createPresentationDefinition(buildDefinition(id, "to-delete", "To Delete"));
        Assert.assertTrue(dao.presentationDefinitionExists(id, TENANT_ID));

        dao.deletePresentationDefinition(id, TENANT_ID);

        Assert.assertFalse(dao.presentationDefinitionExists(id, TENANT_ID));
    }

    private PresentationDefinition buildDefinition(String id, String identifier, String displayName) {

        return new PresentationDefinition.Builder()
                .definitionId(id)
                .identifier(identifier)
                .displayName(displayName)
                .description(DESCRIPTION)
                .tenantId(TENANT_ID)
                .build();
    }
}
