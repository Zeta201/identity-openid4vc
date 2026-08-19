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

package org.wso2.carbon.identity.openid4vc.presentation.management.service.impl;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.openid4vc.presentation.management.cache.PresentationDefinitionCache;
import org.wso2.carbon.identity.openid4vc.presentation.management.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationManagementErrorCode;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.presentation.management.model.PresentationDefinition.RequestedCredential;

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PresentationDefinitionServiceImpl}.
 *
 * <p>DAO interactions are mocked via Mockito. Tests for {@code updatePresentationDefinition} and
 * {@code deletePresentationDefinition} use {@code MockedStatic} (mockito-inline) to intercept
 * {@link PresentationDefinitionCache#getInstance()} and
 * {@link IdentityTenantUtil#getTenantDomain(int)} before they touch OSGi services.</p>
 */
public class PresentationDefinitionServiceImplTest {

    private static final int TENANT_ID = 1;
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String DEFINITION_ID = "test-def-id";
    private static final String DEFINITION_NAME = "Test Definition";

    private PresentationDefinitionDAO mockDao;
    private PresentationDefinitionServiceImpl service;

    @BeforeMethod
    public void setUp() {

        mockDao = Mockito.mock(PresentationDefinitionDAO.class);
        service = new PresentationDefinitionServiceImpl(mockDao);
    }

    @Test(priority = 1,
        description = "Test that createPresentationDefinition throws a validation error when definition is null")
    public void testCreateDefinitionWithNullDefinitionThrowsValidationError() throws Exception {

        try {
            // Execute test — null input should fail validation
            service.createPresentationDefinition(null, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for a null definition");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 2,
        description = "Test that createPresentationDefinition throws a validation error when definition name is blank")
    public void testCreateDefinitionWithBlankNameThrowsValidationError() throws Exception {

        // Set up a definition with a blank name
        PresentationDefinition pd = new PresentationDefinition.Builder()
                .name("   ")
                .build();

        try {
            // Execute test
            service.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for a blank definition name");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 3,
        description = "Test createPresentationDefinition rejects a credential ID with invalid characters")
    public void testCreateDefinitionWithInvalidCredentialIdThrowsValidationError() throws Exception {

        // Set up a credential with spaces and special characters in its ID
        RequestedCredential cred = new RequestedCredential();
        cred.setCredentialId("invalid id with spaces!");

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .name(DEFINITION_NAME)
                .requestedCredentials(Collections.singletonList(cred))
                .build();

        try {
            // Execute test
            service.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for an invalid credential ID");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 4,
        description = "Test that createPresentationDefinition throws a validation error when a credential ID is blank")
    public void testCreateDefinitionWithBlankCredentialIdThrowsValidationError() throws Exception {

        // Set up a credential with a blank ID
        RequestedCredential cred = new RequestedCredential();
        cred.setCredentialId("   ");

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .name(DEFINITION_NAME)
                .requestedCredentials(Collections.singletonList(cred))
                .build();

        try {
            // Execute test
            service.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for a blank credential ID");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 5,
        description = "Test that createPresentationDefinition generates a UUID when the definition ID is blank")
    public void testCreateDefinitionWithBlankIdGeneratesUuid() throws Exception {

        // Set up a definition with no explicit ID
        when(mockDao.presentationDefinitionExists(anyString(), eq(TENANT_ID))).thenReturn(false);
        PresentationDefinition pd = new PresentationDefinition.Builder()
                .name(DEFINITION_NAME)
                .build();

        // Execute test
        PresentationDefinition result = service.createPresentationDefinition(pd, TENANT_ID);

        // Verify a UUID was generated
        Assert.assertNotNull(result.getDefinitionId(),
                "definitionId should be generated and not null when not provided");
        Assert.assertTrue(result.getDefinitionId().length() > 0,
                "Expected a generated UUID definition ID, got blank");
    }

    @Test(priority = 6,
        description = "Test createPresentationDefinition throws DEFINITION_ALREADY_EXISTS for a duplicate ID")
    public void testCreateDefinitionWithDuplicateIdThrowsAlreadyExists() throws Exception {

        // Set up — DAO reports the definition already exists
        when(mockDao.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name(DEFINITION_NAME)
                .build();

        try {
            // Execute test
            service.createPresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.DEFINITION_ALREADY_EXISTS,
                    "Error code should be DEFINITION_ALREADY_EXISTS for a duplicate definition ID");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 7,
        description = "Test that createPresentationDefinition saves the definition and returns it with all fields set")
    public void testCreateDefinitionSuccessSavesAndReturnsDefinition() throws Exception {

        // Set up — definition does not yet exist
        when(mockDao.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(false);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name(DEFINITION_NAME)
                .description("A test description")
                .build();

        // Execute test
        PresentationDefinition result = service.createPresentationDefinition(pd, TENANT_ID);

        // Verify
        Assert.assertEquals(result.getDefinitionId(), DEFINITION_ID,
                "Returned definition ID should match the provided ID");
        Assert.assertEquals(result.getName(), DEFINITION_NAME,
                "Returned definition name should match the provided name");
        Assert.assertEquals(result.getTenantId(), TENANT_ID,
                "Returned definition tenant ID should match the provided tenant ID");
        verify(mockDao).createPresentationDefinition(any(PresentationDefinition.class));
    }

    @Test(priority = 8,
        description = "Test that getPresentationDefinitionById throws a validation error when the ID is blank")
    public void testGetDefinitionByIdWithBlankIdThrowsValidationError() throws Exception {

        try {
            // Execute test — blank ID should fail validation
            service.getPresentationDefinitionById("  ", TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for a blank definition ID");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 9,
        description = "Test getPresentationDefinitionById throws DEFINITION_NOT_FOUND when not found")
    public void testGetDefinitionByIdWhenNotFoundThrowsDefinitionNotFound() throws Exception {

        // Set up — DAO returns null for missing definition
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        try {
            // Execute test
            service.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.DEFINITION_NOT_FOUND,
                    "Error code should be DEFINITION_NOT_FOUND when the definition does not exist");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 10,
        description = "Test that getPresentationDefinitionById returns the correct definition when it exists")
    public void testGetDefinitionByIdSuccess() throws Exception {

        // Set up — DAO returns the expected definition
        PresentationDefinition expected = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(expected);

        // Execute test
        PresentationDefinition result = service.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID);

        // Verify
        Assert.assertEquals(result.getDefinitionId(), DEFINITION_ID,
                "Returned definition ID should match the requested ID");
    }

    @Test(priority = 11,
        description = "Test that getAllPresentationDefinitions delegates to the DAO and returns all definitions")
    public void testGetAllDefinitionsDelegatesToDao() throws Exception {

        // Set up — DAO returns a single-element list
        List<PresentationDefinition> defs = Collections.singletonList(
                buildDefinition(DEFINITION_ID, DEFINITION_NAME));
        when(mockDao.getAllPresentationDefinitions(TENANT_ID)).thenReturn(defs);

        // Execute test
        List<PresentationDefinition> result = service.getAllPresentationDefinitions(TENANT_ID);

        // Verify
        Assert.assertEquals(result.size(), 1,
                "Result list should have exactly 1 element");
        Assert.assertEquals(result.get(0).getDefinitionId(), DEFINITION_ID,
                "The single returned definition should have the expected ID");
    }

    @Test(priority = 12,
        description = "Test that presentationDefinitionExists delegates to the DAO and returns the correct boolean")
    public void testDefinitionExistsDelegatesToDao() throws Exception {

        // Set up
        when(mockDao.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        // Execute test and verify
        Assert.assertTrue(service.presentationDefinitionExists(DEFINITION_ID, TENANT_ID),
                "presentationDefinitionExists should return true when DAO reports the definition exists");
    }

    @Test(priority = 13,
        description = "Test that getPresentationDefinitionByName throws a validation error when the name is blank")
    public void testGetDefinitionByNameWithBlankNameThrowsValidationError() throws Exception {

        try {
            // Execute test — blank name should fail validation
            service.getPresentationDefinitionByName("   ", TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for a blank definition name");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 14,
        description = "Test getPresentationDefinitionByName delegates to the DAO and returns the definition")
    public void testGetDefinitionByNameSuccessDelegatesToDao() throws Exception {

        // Set up
        PresentationDefinition expected = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionByName(DEFINITION_NAME, TENANT_ID)).thenReturn(expected);

        // Execute test
        PresentationDefinition result = service.getPresentationDefinitionByName(DEFINITION_NAME, TENANT_ID);

        // Verify
        Assert.assertEquals(result.getName(), DEFINITION_NAME,
                "Returned definition name should match the queried name");
    }

    @Test(priority = 15,
        description = "Test updatePresentationDefinition throws DEFINITION_NOT_FOUND when not found")
    public void testUpdateDefinitionWhenNotFoundThrowsDefinitionNotFound() throws Exception {

        // Set up — DAO returns null for the definition
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("New Name")
                .build();

        try {
            // Execute test
            service.updatePresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.DEFINITION_NOT_FOUND,
                    "Error code should be DEFINITION_NOT_FOUND when the definition does not exist");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 16,
        description = "Test updatePresentationDefinition throws validation error for an invalid credential ID")
    public void testUpdateDefinitionWithInvalidCredentialIdThrowsValidationError() throws Exception {

        // Set up — existing definition found, but the update contains a bad credential ID
        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);

        RequestedCredential badCred = new RequestedCredential();
        badCred.setCredentialId("bad id!");

        PresentationDefinition pd = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Updated Name")
                .requestedCredentials(Collections.singletonList(badCred))
                .build();

        try {
            // Execute test
            service.updatePresentationDefinition(pd, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.VALIDATION_ERROR,
                    "Error code should be VALIDATION_ERROR for an invalid credential ID in the update");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 17,
        description = "Test that updatePresentationDefinition merges the new name and invalidates the cache on success")
    public void testUpdateDefinitionSuccessMergesNameAndInvalidatesCache() throws Exception {

        // Set up
        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);

        PresentationDefinition update = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Updated Name")
                .build();

        try (MockedStatic<PresentationDefinitionCache> mockedCache =
                     Mockito.mockStatic(PresentationDefinitionCache.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil =
                     Mockito.mockStatic(IdentityTenantUtil.class)) {

            PresentationDefinitionCache mockCacheInst = Mockito.mock(PresentationDefinitionCache.class);
            mockedCache.when(PresentationDefinitionCache::getInstance).thenReturn(mockCacheInst);
            mockedTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                    .thenReturn(TENANT_DOMAIN);

            // Execute test
            PresentationDefinition result = service.updatePresentationDefinition(update, TENANT_ID);

            // Verify
            Assert.assertEquals(result.getName(), "Updated Name",
                    "The returned definition should have the updated name");
            Assert.assertEquals(result.getDefinitionId(), DEFINITION_ID,
                    "The returned definition ID should be unchanged");
            verify(mockDao).updatePresentationDefinition(
                    any(PresentationDefinition.class), anyList(), eq(TENANT_ID));
            verify(mockCacheInst).remove(TENANT_DOMAIN, DEFINITION_ID);
        }
    }

    @Test(priority = 18,
        description = "Test updatePresentationDefinition keeps existing name when the update name is blank")
    public void testUpdateDefinitionFallsBackToExistingNameWhenBlank() throws Exception {

        // Set up — null name in the update should preserve the existing name
        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);

        PresentationDefinition update = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name(null)
                .build();

        try (MockedStatic<PresentationDefinitionCache> mockedCache =
                     Mockito.mockStatic(PresentationDefinitionCache.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil =
                     Mockito.mockStatic(IdentityTenantUtil.class)) {

            PresentationDefinitionCache mockCacheInst = Mockito.mock(PresentationDefinitionCache.class);
            mockedCache.when(PresentationDefinitionCache::getInstance).thenReturn(mockCacheInst);
            mockedTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                    .thenReturn(TENANT_DOMAIN);

            // Execute test
            PresentationDefinition result = service.updatePresentationDefinition(update, TENANT_ID);

            // Verify the existing name was preserved
            Assert.assertEquals(result.getName(), DEFINITION_NAME,
                    "Expected the existing name to be preserved when update name is blank");
        }
    }

    @Test(priority = 19,
        description = "Test deletePresentationDefinition throws DEFINITION_NOT_FOUND when not found")
    public void testDeleteDefinitionWhenNotFoundThrowsDefinitionNotFound() throws Exception {

        // Set up — DAO returns null for the definition
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        try {
            // Execute test
            service.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.DEFINITION_NOT_FOUND,
                    "Error code should be DEFINITION_NOT_FOUND when the definition does not exist");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 20,
        description = "Test deletePresentationDefinition throws DEFINITION_IN_USE when referenced by an application")
    public void testDeleteDefinitionWhenInUseThrowsDefinitionInUse() throws Exception {

        // Set up — definition exists but is in use
        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);
        when(mockDao.isDefinitionInUse(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        try {
            // Execute test
            service.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.DEFINITION_IN_USE,
                    "Error code should be DEFINITION_IN_USE when the definition is still referenced");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException");
    }

    @Test(priority = 21,
        description = "Test deletePresentationDefinition deletes and invalidates the cache on success")
    public void testDeleteDefinitionSuccessDeletesAndInvalidatesCache() throws Exception {

        // Set up — definition exists and is not in use
        PresentationDefinition existing = buildDefinition(DEFINITION_ID, DEFINITION_NAME);
        when(mockDao.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(existing);
        when(mockDao.isDefinitionInUse(DEFINITION_ID, TENANT_ID)).thenReturn(false);

        try (MockedStatic<PresentationDefinitionCache> mockedCache =
                     Mockito.mockStatic(PresentationDefinitionCache.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil =
                     Mockito.mockStatic(IdentityTenantUtil.class)) {

            PresentationDefinitionCache mockCacheInst = Mockito.mock(PresentationDefinitionCache.class);
            mockedCache.when(PresentationDefinitionCache::getInstance).thenReturn(mockCacheInst);
            mockedTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                    .thenReturn(TENANT_DOMAIN);

            // Execute test
            service.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);

            // Verify the definition was deleted and cache was invalidated
            verify(mockDao).deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
            verify(mockCacheInst).remove(TENANT_DOMAIN, DEFINITION_ID);
        }
    }

    private PresentationDefinition buildDefinition(String id, String name) {

        return new PresentationDefinition.Builder()
                .definitionId(id)
                .name(name)
                .tenantId(TENANT_ID)
                .build();
    }
}
