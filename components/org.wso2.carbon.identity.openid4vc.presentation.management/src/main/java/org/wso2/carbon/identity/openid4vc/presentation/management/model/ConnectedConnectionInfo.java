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

package org.wso2.carbon.identity.openid4vc.presentation.management.model;

/**
 * Domain model for a connection (IDP) that references a presentation definition.
 */
public class ConnectedConnectionInfo {

    private String connectionId;
    private String connectionName;

    public ConnectedConnectionInfo(String connectionId, String connectionName) {

        this.connectionId = connectionId;
        this.connectionName = connectionName;
    }

    public String getConnectionId() {

        return connectionId;
    }

    public void setConnectionId(String connectionId) {

        this.connectionId = connectionId;
    }

    public String getConnectionName() {

        return connectionName;
    }

    public void setConnectionName(String connectionName) {

        this.connectionName = connectionName;
    }
}
