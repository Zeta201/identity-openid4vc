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

package org.wso2.carbon.identity.openid4vc.presentation.management.util;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationManagementErrorCode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Unit tests for {@link PresentationDefinitionFilterUtil}.
 *
 * <p>This is a pure utility class with no dependencies on OSGi or database state.
 * All tests operate against the real {@link org.wso2.carbon.identity.core.model.FilterTreeBuilder}
 * parser, which validates that the generated filter strings are syntactically correct.</p>
 */
public class PresentationDefinitionFilterUtilTest {

    @Test(priority = 1,
        description = "Test that getExpressionNodes returns an empty list when the filter is blank")
    public void testGetExpressionNodesWithBlankFilterReturnsEmptyList() throws Exception {

        // Execute test
        List<ExpressionNode> nodes = PresentationDefinitionFilterUtil.getExpressionNodes("");

        // Verify
        Assert.assertTrue(nodes.isEmpty(),
                "Expected empty list for a blank filter string");
    }

    @Test(priority = 2,
        description = "Test that getExpressionNodes returns an empty list when the filter is null")
    public void testGetExpressionNodesWithNullFilterReturnsEmptyList() throws Exception {

        // Execute test
        List<ExpressionNode> nodes = PresentationDefinitionFilterUtil.getExpressionNodes(null);

        // Verify
        Assert.assertTrue(nodes.isEmpty(),
                "Expected empty list for a null filter");
    }

    @Test(priority = 3,
        description = "Test that getExpressionNodes parses a 'name eq' filter into a single expression node")
    public void testGetExpressionNodesWithNameEqFilterReturnsOneNode() throws Exception {

        // Execute test
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("name eq \"test\"");

        // Verify the parsed expression node
        Assert.assertEquals(nodes.size(), 1,
                "Expected exactly 1 expression node");
        Assert.assertEquals(nodes.get(0).getAttributeValue(), "name",
                "Attribute should be 'name'");
        Assert.assertEquals(nodes.get(0).getOperation(), "eq",
                "Operation should be 'eq'");
        Assert.assertEquals(nodes.get(0).getValue(), "test",
                "Value should be 'test'");
    }

    @Test(priority = 4,
        description = "Test that getExpressionNodes parses a 'description sw' filter into a single expression node")
    public void testGetExpressionNodesWithDescriptionSwFilterReturnsOneNode() throws Exception {

        // Execute test
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("description sw \"ID\"");

        // Verify the parsed expression node
        Assert.assertEquals(nodes.size(), 1,
                "Expected exactly 1 expression node");
        Assert.assertEquals(nodes.get(0).getAttributeValue(), "description",
                "Attribute should be 'description'");
        Assert.assertEquals(nodes.get(0).getOperation(), "sw",
                "Operation should be 'sw'");
        Assert.assertEquals(nodes.get(0).getValue(), "ID",
                "Value should be 'ID'");
    }

    @Test(priority = 5,
        description = "Test that getExpressionNodes throws a client exception for syntactically invalid filter strings")
    public void testGetExpressionNodesWithInvalidSyntaxThrowsClientException() {

        try {
            // Execute test — gibberish filter should fail parsing
            PresentationDefinitionFilterUtil.getExpressionNodes("!@#$%^&*");
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.INVALID_FILTER,
                    "Error code should be INVALID_FILTER for a syntactically invalid filter");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException for invalid filter");
    }

    @Test(priority = 6,
        description = "Test that getExpressionNodes with an 'after' cursor adds a gt cursor expression node")
    public void testGetExpressionNodesWithAfterCursorAddsCursorNode() throws Exception {

        // Set up — encode a cursor value as Base64
        String cursorValue = "10";
        String after = Base64.getEncoder().encodeToString(
                cursorValue.getBytes(StandardCharsets.UTF_8));

        // Execute test
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes(null, after, null);

        // Verify the cursor expression node
        Assert.assertEquals(nodes.size(), 1,
                "Expected exactly 1 expression node for the after cursor");
        Assert.assertEquals(nodes.get(0).getAttributeValue(), "after",
                "Attribute should be 'after' for an after cursor");
        Assert.assertEquals(nodes.get(0).getOperation(), "gt",
                "Operation should be 'gt' for an after cursor");
        Assert.assertEquals(nodes.get(0).getValue(), cursorValue,
                "Value should be the decoded cursor value");
    }

    @Test(priority = 7,
        description = "Test that getExpressionNodes with a 'before' cursor adds a lt cursor expression node")
    public void testGetExpressionNodesWithBeforeCursorAddsCursorNode() throws Exception {

        // Set up — encode a cursor value as Base64
        String cursorValue = "25";
        String before = Base64.getEncoder().encodeToString(
                cursorValue.getBytes(StandardCharsets.UTF_8));

        // Execute test
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes(null, null, before);

        // Verify the cursor expression node
        Assert.assertEquals(nodes.size(), 1,
                "Expected exactly 1 expression node for the before cursor");
        Assert.assertEquals(nodes.get(0).getAttributeValue(), "before",
                "Attribute should be 'before' for a before cursor");
        Assert.assertEquals(nodes.get(0).getOperation(), "lt",
                "Operation should be 'lt' for a before cursor");
        Assert.assertEquals(nodes.get(0).getValue(), cursorValue,
                "Value should be the decoded cursor value");
    }

    @Test(priority = 8,
        description = "Test that getExpressionNodes combines a filter expression and an after cursor into two nodes")
    public void testGetExpressionNodesWithFilterAndAfterCursorCombinesIntoTwoNodes() throws Exception {

        // Set up — combine a name filter with an after cursor
        String cursorValue = "5";
        String after = Base64.getEncoder().encodeToString(
                cursorValue.getBytes(StandardCharsets.UTF_8));

        // Execute test
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("name eq \"foo\"", after, null);

        // Verify both expression nodes are present
        Assert.assertEquals(nodes.size(), 2,
                "Expected 2 expression nodes: one for the name eq filter and one for the cursor");
    }

    @Test(priority = 9,
        description = "Test that getExpressionNodes with no cursors returns only the filter expression nodes")
    public void testGetExpressionNodesWithNoCursorsReturnsOnlyFilterNodes() throws Exception {

        // Execute test — no cursors provided
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("name eq \"bar\"", null, null);

        // Verify only the filter node is returned
        Assert.assertEquals(nodes.size(), 1,
                "Expected exactly 1 expression node when no cursors are provided");
        Assert.assertEquals(nodes.get(0).getAttributeValue(), "name",
                "The single node's attribute should be 'name'");
    }

    @Test(priority = 10,
        description = "Test that getFilterQueryBuilder returns an empty query for an empty expression list")
    public void testGetFilterQueryBuilderWithEmptyListReturnsEmptyQuery() throws Exception {

        // Execute test
        PresentationDefinitionFilterQueryBuilder builder =
                PresentationDefinitionFilterUtil.getFilterQueryBuilder(Collections.emptyList());

        // Verify
        Assert.assertNotNull(builder,
                "Builder should not be null even for an empty expression list");
        Assert.assertTrue(builder.getFilterQuery() == null || builder.getFilterQuery().isEmpty(),
                "Expected empty filter query for an empty expression list");
    }

    @Test(priority = 11,
        description = "Test that getFilterQueryBuilder builds an equality SQL clause for an 'eq' operation")
    public void testGetFilterQueryBuilderWithEqOperationBuildsEqualityClause() throws Exception {

        // Set up — parse a name eq filter
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("name eq \"testName\"");

        // Execute test
        PresentationDefinitionFilterQueryBuilder builder =
                PresentationDefinitionFilterUtil.getFilterQueryBuilder(nodes);

        // Verify the SQL clause
        Assert.assertTrue(builder.getFilterQuery().contains("NAME = ?"),
                "Expected 'NAME = ?' in SQL clause for eq operation, got: " + builder.getFilterQuery());
        Assert.assertEquals(builder.getFilterAttributeValue().get(1), "testName",
                "Filter value should be 'testName'");
    }

    @Test(priority = 12,
        description = "Test that getFilterQueryBuilder builds a starts-with LIKE clause for a 'sw' operation")
    public void testGetFilterQueryBuilderWithSwOperationBuildsStartsWithLikeClause() throws Exception {

        // Set up — parse a name sw filter
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("name sw \"prefix\"");

        // Execute test
        PresentationDefinitionFilterQueryBuilder builder =
                PresentationDefinitionFilterUtil.getFilterQueryBuilder(nodes);

        // Verify the SQL LIKE clause with trailing wildcard
        Assert.assertTrue(builder.getFilterQuery().contains("NAME LIKE ?"),
                "Expected 'NAME LIKE ?' in SQL clause for sw operation");
        Assert.assertEquals(builder.getFilterAttributeValue().get(1), "prefix%",
                "Filter value should have a trailing wildcard for sw operation");
    }

    @Test(priority = 13,
        description = "Test that getFilterQueryBuilder builds an ends-with LIKE clause for an 'ew' operation")
    public void testGetFilterQueryBuilderWithEwOperationBuildsEndsWithLikeClause() throws Exception {

        // Set up — parse a name ew filter
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("name ew \"suffix\"");

        // Execute test
        PresentationDefinitionFilterQueryBuilder builder =
                PresentationDefinitionFilterUtil.getFilterQueryBuilder(nodes);

        // Verify the SQL LIKE clause with leading wildcard
        Assert.assertTrue(builder.getFilterQuery().contains("NAME LIKE ?"),
                "Expected 'NAME LIKE ?' in SQL clause for ew operation");
        Assert.assertEquals(builder.getFilterAttributeValue().get(1), "%suffix",
                "Filter value should have a leading wildcard for ew operation");
    }

    @Test(priority = 14,
        description = "Test that getFilterQueryBuilder builds a contains LIKE clause for a 'co' operation")
    public void testGetFilterQueryBuilderWithCoOperationBuildsContainsLikeClause() throws Exception {

        // Set up — parse a description co filter
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("description co \"keyword\"");

        // Execute test
        PresentationDefinitionFilterQueryBuilder builder =
                PresentationDefinitionFilterUtil.getFilterQueryBuilder(nodes);

        // Verify the SQL LIKE clause with both wildcards
        Assert.assertTrue(builder.getFilterQuery().contains("DESCRIPTION LIKE ?"),
                "Expected 'DESCRIPTION LIKE ?' in SQL clause for co operation");
        Assert.assertEquals(builder.getFilterAttributeValue().get(1), "%keyword%",
                "Filter value should have both leading and trailing wildcards for co operation");
    }

    @Test(priority = 15,
        description = "Test getFilterQueryBuilder throws INVALID_FILTER for an attribute not in the column map")
    public void testGetFilterQueryBuilderWithUnsupportedAttributeThrowsInvalidFilter() throws Exception {

        // The filter is syntactically valid so the parser accepts it, but the attribute
        // "unknown_attr" is not in ATTRIBUTE_COLUMN_MAP — should throw INVALID_FILTER.
        List<ExpressionNode> nodes =
                PresentationDefinitionFilterUtil.getExpressionNodes("unknown_attr eq \"value\"");

        try {
            // Execute test
            PresentationDefinitionFilterUtil.getFilterQueryBuilder(nodes);
        } catch (PresentationManagementClientException e) {
            // Verify
            Assert.assertEquals(e.getErrorCode(), PresentationManagementErrorCode.INVALID_FILTER,
                    "Error code should be INVALID_FILTER for an unsupported filter attribute");
            return;
        }
        throw new AssertionError("Expected PresentationManagementClientException for unsupported attribute");
    }
}
