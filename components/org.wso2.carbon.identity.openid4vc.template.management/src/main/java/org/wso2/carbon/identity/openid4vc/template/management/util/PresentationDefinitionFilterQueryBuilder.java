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

package org.wso2.carbon.identity.openid4vc.template.management.util;

import java.util.HashMap;
import java.util.Map;

/**
 * Holds the WHERE clause fragment and its positional parameter values for
 * dynamic presentation definition list queries.
 */
public class PresentationDefinitionFilterQueryBuilder {

    private Map<Integer, String> filterParameterValues;
    private String filterQuery;

    public Map<Integer, String> getFilterAttributeValue() {

        return filterParameterValues;
    }

    public void setFilterAttributeValue(int parameterIndex, String parameterValue) {

        if (filterParameterValues == null) {
            filterParameterValues = new HashMap<>();
        }
        filterParameterValues.put(parameterIndex, parameterValue);
    }

    public void setFilterQuery(String filterQuery) {

        this.filterQuery = filterQuery;
    }

    public String getFilterQuery() {

        return filterQuery;
    }
}
