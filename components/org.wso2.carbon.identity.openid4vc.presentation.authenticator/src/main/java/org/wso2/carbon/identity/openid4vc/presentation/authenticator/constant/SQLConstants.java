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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant;

/**
 * SQL queries for the VP session store.
 */
public final class SQLConstants {

    private SQLConstants() {

    }

    public static final String TABLE_NAME = "IDN_VP_SESSION_STORE";

    public static final String INSERT =
            "INSERT INTO " + TABLE_NAME + " (SESSION_ID, TENANT_ID, SESSION_DATA, CREATED_AT, EXPIRES_AT) " +
            "VALUES (?, ?, ?, ?, ?)";

    public static final String UPDATE =
            "UPDATE " + TABLE_NAME + " SET SESSION_DATA = ?, EXPIRES_AT = ? WHERE SESSION_ID = ?";

    public static final String SELECT =
            "SELECT SESSION_DATA, EXPIRES_AT FROM " + TABLE_NAME + " WHERE SESSION_ID = ?";

    public static final String DELETE =
            "DELETE FROM " + TABLE_NAME + " WHERE SESSION_ID = ?";

    public static final String DELETE_EXPIRED =
            "DELETE FROM " + TABLE_NAME + " WHERE EXPIRES_AT < ?";

    public static final String DELETE_BY_TENANT =
            "DELETE FROM " + TABLE_NAME + " WHERE TENANT_ID = ?";
}
