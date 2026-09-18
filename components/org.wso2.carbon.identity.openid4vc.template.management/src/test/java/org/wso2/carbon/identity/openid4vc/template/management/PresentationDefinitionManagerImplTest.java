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

package org.wso2.carbon.identity.openid4vc.template.management;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.template.management.constant.PresentationDefinitionManagementConstants.ErrorMessages;
import org.wso2.carbon.identity.openid4vc.template.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.template.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.template.management.model.Credential;
import org.wso2.carbon.identity.openid4vc.template.management.model.PresentationDefinition;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PresentationDefinitionManagerImpl}.
 *
 * <p>All DAO interactions are mocked via Mockito. The singleton DAO field is replaced with a mock
 * before each test via reflection. Cache invalidation is handled inside
 * {@link org.wso2.carbon.identity.openid4vc.template.management.dao.impl.CacheBackedPresentationDefinitionDAO}
 * and is not exercised here.</p>
 */
public class PresentationDefinitionManagerImplTest {

    private static final int TENANT_ID = 1;
    private static final String DEFINITION_ID = "test-def-id";
    private static final String DEFINITION_IDENTIFIER = "test-definition";
    private static final String DEFINITION_DISPLAY_NAME = "Test Definition";

    private PresentationDefinitionDAO mockDao;
    private PresentationDefinitionManager manager;

    @BeforeMethod
    public void setUp() throws Exception {

        mockDao = Mockito.mock(PresentationDefinitionDAO.class);
        manager = PresentationDefinitionManagerImpl.getInstance();

        // PresentationDefinitionManagerImpl is a singleton with a private constructor.
        // Inject the mock DAO directly into the instance field for test isolation.
        Field daoField = PresentationDefinitionManagerImpl.class.getDeclaredField("presentationDefinitionDAO");
        daoField.setAccessible(true);
        daoField.set(manager, mockDao);
    }

    @Test(priority = 1,
            description = "createPresentationDefinition throws a validation error when definition is null")
    public void testCreateDefinitionWithNullDefinitionThrowsValidationError() throws Exception {

        try {
            manager.createPresentationDefinition(null, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 2,
            description = "createPresentationDefinition throws a validation error when identifier is blank")
    public void testCreateDefinitionWithBlankIdentifierThrowsValidationError() throws Exception {

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .identifier("   ")
                .displayName(DEFINITION_DISPLAY_NAME)
                .build();

        try {
            manager.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 3,
            description = "createPresentationDefinition rejects a credential identifier with invalid characters")
    public void testCreateDefinitionWithInvalidCredentialIdThrowsValidationError() throws Exception {

        Credential cred = new Credential();
        cred.setIdentifier("invalid id with spaces!");

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .identifier(DEFINITION_IDENTIFIER)
                .displayName(DEFINITION_DISPLAY_NAME)
                .credentials(Collections.singletonList(cred))
                .build();

        try {
            manager.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 4,
            description = "createPresentationDefinition throws a validation error for a blank credential identifier")
    public void testCreateDefinitionWithBlankCredentialIdThrowsValidationError() throws Exception {

        Credential cred = new Credential();
        cred.setIdentifier("   ");

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .identifier(DEFINITION_IDENTIFIER)
                .displayName(DEFINITION_DISPLAY_NAME)
                .credentials(Collections.singletonList(cred))
                .build();

        try {
            manager.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 5,
            description = "createPresentationDefinition always generates an internal UUID for the definition ID")
    public void testCreateDefinitionAlwaysGeneratesUuid() throws Exception {

        when(mockDao.presentationDefinitionIdentifierExists(anyString(), eq(TENANT_ID))).thenReturn(false);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .identifier(DEFINITION_IDENTIFIER)
                .displayName(DEFINITION_DISPLAY_NAME)
                .build();

        PresentationDefinition result = manager.createPresentationDefinition(pd, TENANT_ID);

        Assert.assertNotNull(result.getId(), "id should be a generated UUID, not null");
        Assert.assertFalse(result.getId().isEmpty(), "id should not be blank");
    }

    @Test(priority = 6,
            description = "createPresentationDefinition throws DEFINITION_ALREADY_EXISTS for a duplicate identifier")
    public void testCreateDefinitionWithDuplicateIdentifierThrowsAlreadyExists() throws Exception {

        when(mockDao.presentationDefinitionIdentifierExists(DEFINITION_IDENTIFIER, TENANT_ID)).thenReturn(true);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .identifier(DEFINITION_IDENTIFIER)
                .displayName(DEFINITION_DISPLAY_NAME)
                .build();

        try {
            manager.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_DEFINITION_ALREADY_EXISTS.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 7,
            description = "createPresentationDefinition saves the definition and returns it with all fields set")
    public void testCreateDefinitionSuccessSavesAndReturnsDefinition() throws Exception {

        when(mockDao.presentationDefinitionIdentifierExists(DEFINITION_IDENTIFIER, TENANT_ID)).thenReturn(false);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .identifier(DEFINITION_IDENTIFIER)
                .displayName(DEFINITION_DISPLAY_NAME)
                .description("A test description")
                .build();

        PresentationDefinition result = manager.createPresentationDefinition(pd, TENANT_ID);

        Assert.assertNotNull(result.getId(), "Returned definition ID should be a generated UUID");
        Assert.assertEquals(result.getIdentifier(), DEFINITION_IDENTIFIER);
        Assert.assertEquals(result.getDisplayName(), DEFINITION_DISPLAY_NAME);
        Assert.assertEquals(result.getTenantId(), TENANT_ID);
        verify(mockDao).createPresentationDefinition(any(PresentationDefinition.class));
    }

    @Test(priority = 8,
            description = "getPresentationDefinitionById throws a validation error when the ID is blank")
    public void testGetDefinitionByIdWithBlankIdThrowsValidationError() throws Exception {

        try {
            manager.getPresentationDefinitionById("  ", TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 9,
            description = "getPresentationDefinitionById throws DEFINITION_NOT_FOUND when the definition is absent")
    public void testGetDefinitionByIdWhenNotFoundThrowsDefinitionNotFound() throws Exception {

        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        try {
            manager.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_DEFINITION_NOT_FOUND.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 10,
            description = "getPresentationDefinitionById returns the correct definition when it exists")
    public void testGetDefinitionByIdSuccess() throws Exception {

        PresentationDefinition expected = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(expected);

        PresentationDefinition result = manager.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID);

        Assert.assertEquals(result.getId(), DEFINITION_ID);
    }

    @Test(priority = 11,
            description = "getAllPresentationDefinitions delegates to the DAO and returns all definitions")
    public void testGetAllDefinitionsDelegatesToDao() throws Exception {

        List<PresentationDefinition> defs = Collections.singletonList(
                buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME));
        when(mockDao.getAllPresentationDefinitions(TENANT_ID)).thenReturn(defs);

        List<PresentationDefinition> result = manager.getAllPresentationDefinitions(TENANT_ID);

        Assert.assertEquals(result.size(), 1);
        Assert.assertEquals(result.get(0).getId(), DEFINITION_ID);
    }

    @Test(priority = 12,
            description = "presentationDefinitionExists delegates to the DAO and returns the correct boolean")
    public void testDefinitionExistsDelegatesToDao() throws Exception {

        when(mockDao.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        Assert.assertTrue(manager.presentationDefinitionExists(DEFINITION_ID, TENANT_ID));
    }

    @Test(priority = 13,
            description = "getPresentationDefinitionByIdentifier throws a validation error when identifier is blank")
    public void testGetDefinitionByIdentifierWithBlankIdentifierThrowsValidationError() throws Exception {

        try {
            manager.getPresentationDefinitionByIdentifier("   ", TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 14,
            description = "getPresentationDefinitionByIdentifier delegates to the DAO and returns the definition")
    public void testGetDefinitionByIdentifierSuccessDelegatesToDao() throws Exception {

        PresentationDefinition expected = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionByIdentifier(DEFINITION_IDENTIFIER, TENANT_ID)).thenReturn(expected);

        PresentationDefinition result =
                manager.getPresentationDefinitionByIdentifier(DEFINITION_IDENTIFIER, TENANT_ID);

        Assert.assertEquals(result.getIdentifier(), DEFINITION_IDENTIFIER);
    }

    @Test(priority = 15,
            description = "updatePresentationDefinition throws DEFINITION_NOT_FOUND when the definition is absent")
    public void testUpdateDefinitionWhenNotFoundThrowsDefinitionNotFound() throws Exception {

        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .id(DEFINITION_ID)
                .displayName("New Display Name")
                .build();

        try {
            manager.updatePresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_DEFINITION_NOT_FOUND.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 16,
            description = "updatePresentationDefinition throws a validation error for an invalid credential identifier")
    public void testUpdateDefinitionWithInvalidCredentialIdThrowsValidationError() throws Exception {

        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);

        Credential badCred = new Credential();
        badCred.setIdentifier("bad id!");

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .id(DEFINITION_ID)
                .displayName("Updated Display Name")
                .credentials(Collections.singletonList(badCred))
                .build();

        try {
            manager.updatePresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_VALIDATION_ERROR.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 17,
            description = "updatePresentationDefinition merges the new display name and delegates to the DAO")
    public void testUpdateDefinitionSuccessMergesDisplayNameAndDelegatesToDao() throws Exception {

        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);

        PresentationDefinition update = new PresentationDefinition.Builder()
                .id(DEFINITION_ID)
                .displayName("Updated Display Name")
                .build();

        PresentationDefinition result = manager.updatePresentationDefinition(update, TENANT_ID);

        Assert.assertEquals(result.getDisplayName(), "Updated Display Name");
        Assert.assertEquals(result.getId(), DEFINITION_ID);
        verify(mockDao).updatePresentationDefinition(
                any(PresentationDefinition.class), anyList(), eq(TENANT_ID));
    }

    @Test(priority = 18,
            description = "updatePresentationDefinition falls back to the existing display name when update is blank")
    public void testUpdateDefinitionFallsBackToExistingDisplayNameWhenBlank() throws Exception {

        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);

        PresentationDefinition update = new PresentationDefinition.Builder()
                .id(DEFINITION_ID)
                .displayName(null)
                .build();

        PresentationDefinition result = manager.updatePresentationDefinition(update, TENANT_ID);

        Assert.assertEquals(result.getDisplayName(), DEFINITION_DISPLAY_NAME,
                "Existing display name should be preserved when update display name is blank");
    }

    @Test(priority = 19,
            description = "deletePresentationDefinition throws DEFINITION_NOT_FOUND when the definition is absent")
    public void testDeleteDefinitionWhenNotFoundThrowsDefinitionNotFound() throws Exception {

        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        try {
            manager.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_DEFINITION_NOT_FOUND.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 20,
            description = "deletePresentationDefinition throws DEFINITION_IN_USE when referenced by a connection")
    public void testDeleteDefinitionWhenInUseThrowsDefinitionInUse() throws Exception {

        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);
        when(mockDao.isDefinitionInUse(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        try {
            manager.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            Assert.assertEquals(e.getErrorCode(), ErrorMessages.ERROR_CODE_DEFINITION_IN_USE.getCode());
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 21,
            description = "deletePresentationDefinition delegates to the DAO on success")
    public void testDeleteDefinitionSuccessDelegatesToDao() throws Exception {

        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_DISPLAY_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);
        when(mockDao.isDefinitionInUse(DEFINITION_ID, TENANT_ID)).thenReturn(false);

        manager.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);

        verify(mockDao).deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
    }

    private PresentationDefinition buildDefinition(String id, String displayName) {

        return new PresentationDefinition.Builder()
                .id(id)
                .identifier(DEFINITION_IDENTIFIER)
                .displayName(displayName)
                .tenantId(TENANT_ID)
                .build();
    }
}
