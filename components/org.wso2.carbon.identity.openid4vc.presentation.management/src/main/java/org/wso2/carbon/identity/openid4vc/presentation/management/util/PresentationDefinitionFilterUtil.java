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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.ExpressionNode;
import org.wso2.carbon.identity.core.model.FilterTreeBuilder;
import org.wso2.carbon.identity.core.model.Node;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationManagementClientException;
import org.wso2.carbon.identity.openid4vc.presentation.management.exception.PresentationManagementErrorCode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for presentation definition filter and pagination operations.
 */
public class PresentationDefinitionFilterUtil {

    private PresentationDefinitionFilterUtil() {

    }

    /**
     * Parses the given SCIM-style filter string and appends cursor conditions derived from
     * the {@code after} or {@code before} tokens, returning a flat list of expression nodes
     * ready for SQL generation.
     *
     * @param filter the SCIM-style filter expression; may be null or blank
     * @param after  the base64-encoded lower-bound cursor for forward pagination; may be null or blank
     * @param before the base64-encoded upper-bound cursor for backward pagination; may be null or blank
     * @return the list of {@link ExpressionNode} objects parsed from the combined filter
     * @throws PresentationManagementClientException if the filter expression is syntactically invalid
     */
    public static List<ExpressionNode> getExpressionNodes(String filter, String after, String before)
            throws PresentationManagementClientException {

        String paginatedFilter = getPaginatedFilter(filter, after, before);
        return getExpressionNodes(paginatedFilter);
    }

    /**
     * Parses the given SCIM-style filter expression into a flat list of expression nodes.
     *
     * @param filter the SCIM-style filter expression to parse; may be null or blank
     * @return the list of {@link ExpressionNode} objects, or an empty list if the filter is blank
     * @throws PresentationManagementClientException if the filter expression is syntactically invalid
     */
    public static List<ExpressionNode> getExpressionNodes(String filter)
            throws PresentationManagementClientException {

        List<ExpressionNode> expressionNodes = new ArrayList<>();
        if (StringUtils.isBlank(filter)) {
            return expressionNodes;
        }
        try {
            FilterTreeBuilder filterTreeBuilder = new FilterTreeBuilder(filter);
            Node rootNode = filterTreeBuilder.buildTree();
            setExpressionNodeList(rootNode, expressionNodes);
        } catch (IOException | IdentityException e) {
            throw new PresentationManagementClientException(
                    PresentationManagementErrorCode.INVALID_FILTER,
                    "Invalid filter expression: " + filter, e);
        }
        return expressionNodes;
    }

    /**
     * Translates the given expression nodes into a SQL WHERE clause fragment and collects
     * the positional parameter values into a {@link PresentationDefinitionFilterQueryBuilder}.
     *
     * @param expressionNodes the parsed filter expression nodes to translate
     * @return a {@link PresentationDefinitionFilterQueryBuilder} containing the WHERE clause fragment
     *         and the ordered positional parameter values
     * @throws PresentationManagementClientException if an expression node references an unsupported
     *                                               attribute or filter operation
     */
    public static PresentationDefinitionFilterQueryBuilder getFilterQueryBuilder(
            List<ExpressionNode> expressionNodes) throws PresentationManagementClientException {

        int parameterIndex = 1;
        StringBuilder whereClause = new StringBuilder();
        PresentationDefinitionFilterQueryBuilder filterQueryBuilder = new PresentationDefinitionFilterQueryBuilder();

        if (CollectionUtils.isEmpty(expressionNodes)) {
            filterQueryBuilder.setFilterQuery(StringUtils.EMPTY);
        } else {
            for (ExpressionNode expressionNode : expressionNodes) {
                String operation = expressionNode.getOperation();
                String filterValue = expressionNode.getValue();
                String attributeValue = expressionNode.getAttributeValue();
                String attributeName = Constants.ATTRIBUTE_COLUMN_MAP.get(attributeValue);

                if (attributeName == null) {
                    throw new PresentationManagementClientException(
                            PresentationManagementErrorCode.INVALID_FILTER,
                            "Unsupported filter attribute: " + attributeValue);
                }
                parameterIndex = buildFilterBasedOnOperation(filterQueryBuilder, attributeName, filterValue,
                        operation, parameterIndex, whereClause);
            }
            filterQueryBuilder.setFilterQuery(
                    StringUtils.isBlank(whereClause.toString()) ? StringUtils.EMPTY : whereClause.toString());
        }
        return filterQueryBuilder;
    }

    /**
     * Appends cursor conditions to the given filter string based on the provided {@code after}
     * or {@code before} base64-encoded cursor tokens.
     *
     * @param filter the base filter expression; may be null or blank
     * @param after  the base64-encoded lower-bound cursor for forward pagination; may be null or blank
     * @param before the base64-encoded upper-bound cursor for backward pagination; may be null or blank
     * @return the combined filter string with the cursor condition appended, or the original filter
     *         if neither cursor is provided
     */
    private static String getPaginatedFilter(String filter, String after, String before) {

        String paginatedFilter = StringUtils.isNotBlank(filter) ? filter : StringUtils.EMPTY;
        if (StringUtils.isNotBlank(before)) {
            String decodedCursor = new String(Base64.getDecoder().decode(before), StandardCharsets.UTF_8);
            paginatedFilter += (StringUtils.isNotBlank(paginatedFilter) ? " and " : "")
                    + Constants.BEFORE_LT + decodedCursor;
        } else if (StringUtils.isNotBlank(after)) {
            String decodedCursor = new String(Base64.getDecoder().decode(after), StandardCharsets.UTF_8);
            paginatedFilter += (StringUtils.isNotBlank(paginatedFilter) ? " and " : "")
                    + Constants.AFTER_GT + decodedCursor;
        }
        return paginatedFilter;
    }

    /**
     * Appends a single SQL predicate for the given filter operation to {@code whereClause} and
     * registers the corresponding parameter value in {@code builder}, then returns the incremented
     * parameter index.
     *
     * @param builder        the query builder to register parameter values into
     * @param attributeName  the database column name mapped from the filter attribute
     * @param filterValue    the filter operand value
     * @param operation      the SCIM filter operation (e.g. {@code "eq"}, {@code "sw"})
     * @param parameterIndex the current positional parameter index for JDBC binding
     * @param whereClause    the WHERE clause fragment being built
     * @return the next available positional parameter index after this predicate is appended
     * @throws PresentationManagementClientException if the operation is not supported
     */
    private static int buildFilterBasedOnOperation(PresentationDefinitionFilterQueryBuilder builder,
            String attributeName, String filterValue, String operation, int parameterIndex,
            StringBuilder whereClause) throws PresentationManagementClientException {

        if (StringUtils.isNotBlank(attributeName) && StringUtils.isNotBlank(filterValue)
                && StringUtils.isNotBlank(operation)) {
            switch (operation) {
                case Constants.EQ:
                    whereClause.append(attributeName).append(" = ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, filterValue);
                    break;
                case Constants.SW:
                    whereClause.append(attributeName).append(" LIKE ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, filterValue + "%");
                    break;
                case Constants.EW:
                    whereClause.append(attributeName).append(" LIKE ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, "%" + filterValue);
                    break;
                case Constants.CO:
                    whereClause.append(attributeName).append(" LIKE ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, "%" + filterValue + "%");
                    break;
                case Constants.GE:
                    whereClause.append(attributeName).append(" >= ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, filterValue);
                    break;
                case Constants.LE:
                    whereClause.append(attributeName).append(" <= ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, filterValue);
                    break;
                case Constants.GT:
                    whereClause.append(attributeName).append(" > ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, filterValue);
                    break;
                case Constants.LT:
                    whereClause.append(attributeName).append(" < ? AND ");
                    builder.setFilterAttributeValue(parameterIndex++, filterValue);
                    break;
                default:
                    throw new PresentationManagementClientException(
                            PresentationManagementErrorCode.INVALID_FILTER,
                            "Unsupported filter operation: " + operation);
            }
        }
        return parameterIndex;
    }

    /**
     * Recursively traverses the filter parse tree and collects all leaf {@link ExpressionNode}
     * instances into the given list.
     *
     * @param node            the current node in the filter parse tree
     * @param expressionNodes the list to accumulate leaf expression nodes into
     */
    private static void setExpressionNodeList(Node node, List<ExpressionNode> expressionNodes) {

        if (node instanceof ExpressionNode) {
            expressionNodes.add((ExpressionNode) node);
        } else if (node.getLeftNode() != null) {
            setExpressionNodeList(node.getLeftNode(), expressionNodes);
        }
        if (node.getRightNode() != null) {
            setExpressionNodeList(node.getRightNode(), expressionNodes);
        }
    }
}
