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

package org.wso2.carbon.identity.openid4vc.presentation.authenticator.store;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.constant.SQLConstants;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * JDBC-backed persistence store for {@link VPFlowSession} objects.
 * Sessions are serialized as JSON. Only the cryptographic secret fields —
 * {@code nonce} and {@code ephemeralPrivateKeyJwk} — are encrypted before storage;
 * the remaining non-sensitive fields are stored as plain JSON.
 */
public class VPSessionStore {

    private static final Log LOG = LogFactory.getLog(VPSessionStore.class);

    private static final String FIELD_NONCE = "nonce";
    private static final String FIELD_EPHEMERAL_KEY = "ephemeralPrivateKeyJwk";
    private static final String ENC_SUFFIX = "_enc";

    private static final Gson GSON = new Gson();

    private static final VPSessionStore INSTANCE = new VPSessionStore();

    private VPSessionStore() {
    }

    public static VPSessionStore getInstance() {

        return INSTANCE;
    }

    /**
     * Persists or updates a VP session. Uses try-UPDATE-then-INSERT to avoid
     * duplicate key errors when the wallet updates an existing ACTIVE session.
     *
     * @param requestId the VP session identifier
     * @param session   the session to persist
     * @throws CryptoException If the session secrets cannot be encrypted before storage
     * @throws SQLException    If the database write fails
     */
    public void put(String requestId, VPFlowSession session) throws CryptoException, SQLException {

        byte[] storedBytes = toStoredBytes(session);

        Connection connection = null;
        try {
            connection = IdentityDatabaseUtil.getSessionDBConnection(true);
            if (!update(connection, requestId, storedBytes, session.getExpiresAt())) {
                insert(connection, requestId, session.getTenantId(), storedBytes, session.getExpiresAt());

            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw e;
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    /**
     * Retrieves a VP session by its request ID.
     * Returns {@code null} if the session does not exist or has expired.
     *
     * @param requestId the VP session identifier
     * @return the session, or {@code null}
     * @throws CryptoException If stored session secrets cannot be decrypted
     * @throws SQLException    If the database read fails
     */
    public VPFlowSession get(String requestId) throws CryptoException, SQLException {

        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet resultSet = null;
        try {
            connection = IdentityDatabaseUtil.getSessionDBConnection(false);
            statement = connection.prepareStatement(SQLConstants.SELECT);
            statement.setString(1, requestId);
            resultSet = statement.executeQuery();
            if (!resultSet.next()) {
                return null;
            }
            long expiresAt = resultSet.getLong(2);
            if (System.currentTimeMillis() > expiresAt) {
                // Expired — clean up and treat as not found.
                IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
                connection = null;
                remove(requestId);
                return null;
            }
            return fromStoredBytes(resultSet.getBytes(1));
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, statement);
        }
    }

    /**
     * Deletes a VP session from the store.
     *
     * @param requestId the VP session identifier
     */
    public void remove(String requestId) {

        Connection connection = null;
        PreparedStatement statement = null;
        try {
            connection = IdentityDatabaseUtil.getSessionDBConnection(true);
            statement = connection.prepareStatement(SQLConstants.DELETE);
            statement.setString(1, requestId);
            statement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            LOG.error("Failed to remove VP session for requestId: " + requestId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
        }
    }

    /**
     * Deletes all expired VP sessions. Intended for periodic cleanup tasks.
     */
    public void removeExpired() {

        Connection connection = null;
        PreparedStatement statement = null;
        try {
            connection = IdentityDatabaseUtil.getSessionDBConnection(true);
            statement = connection.prepareStatement(SQLConstants.DELETE_EXPIRED);
            statement.setLong(1, System.currentTimeMillis());
            int deleted = statement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Removed " + deleted + " expired VP sessions from " + SQLConstants.TABLE_NAME + ".");
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            LOG.error("Failed to remove expired VP sessions.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
        }
    }

    /**
     * Deletes all VP sessions for the given tenant. Intended for tenant offboarding and GDPR erasure.
     *
     * @param tenantId the numeric tenant identifier
     */
    public void removeByTenant(int tenantId) {

        Connection connection = null;
        PreparedStatement statement = null;
        try {
            connection = IdentityDatabaseUtil.getSessionDBConnection(true);
            statement = connection.prepareStatement(SQLConstants.DELETE_BY_TENANT);
            statement.setInt(1, tenantId);
            int deleted = statement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Removed " + deleted + " VP sessions for tenantId: " + tenantId
                        + " from " + SQLConstants.TABLE_NAME + ".");
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            LOG.error("Failed to remove VP sessions for tenantId: " + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
        }
    }

    private boolean update(Connection connection, String requestId, byte[] storedBytes, long expiresAt)
            throws SQLException {

        try (PreparedStatement statement = connection.prepareStatement(SQLConstants.UPDATE)) {
            statement.setBytes(1, storedBytes);
            statement.setLong(2, expiresAt);
            statement.setString(3, requestId);
            return statement.executeUpdate() > 0;
        }
    }

    private void insert(Connection connection, String requestId, int tenantId, byte[] storedBytes,
            long expiresAt) throws SQLException {

        try (PreparedStatement statement = connection.prepareStatement(SQLConstants.INSERT)) {
            statement.setString(1, requestId);
            statement.setInt(2, tenantId);
            statement.setBytes(3, storedBytes);
            statement.setLong(4, System.currentTimeMillis());
            statement.setLong(5, expiresAt);
            statement.executeUpdate();
        }
    }

    /**
     * Serializes a {@link VPFlowSession} to JSON, encrypting only the secret fields
     * ({@code nonce} and {@code ephemeralPrivateKeyJwk}) before storage.
     */
    private static byte[] toStoredBytes(VPFlowSession session) throws CryptoException {

        JsonObject json = GSON.toJsonTree(session).getAsJsonObject();

        String nonce = session.getNonce();
        if (nonce != null) {
            json.remove(FIELD_NONCE);
            json.addProperty(FIELD_NONCE + ENC_SUFFIX,
                    CryptoUtil.getDefaultCryptoUtil()
                            .encryptAndBase64Encode(nonce.getBytes(StandardCharsets.UTF_8)));
        }

        String ephemeralKey = session.getEphemeralPrivateKeyJwk();
        if (ephemeralKey != null) {
            json.remove(FIELD_EPHEMERAL_KEY);
            json.addProperty(FIELD_EPHEMERAL_KEY + ENC_SUFFIX,
                    CryptoUtil.getDefaultCryptoUtil()
                            .encryptAndBase64Encode(ephemeralKey.getBytes(StandardCharsets.UTF_8)));
        }

        return GSON.toJson(json).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Deserializes a {@link VPFlowSession} from stored JSON bytes, decrypting the secret fields.
     */
    private static VPFlowSession fromStoredBytes(byte[] storedBytes) throws CryptoException {

        JsonObject json = GSON.fromJson(new String(storedBytes, StandardCharsets.UTF_8), JsonObject.class);

        JsonElement nonceEnc = json.remove(FIELD_NONCE + ENC_SUFFIX);
        if (nonceEnc != null) {
            byte[] decrypted = CryptoUtil.getDefaultCryptoUtil()
                    .base64DecodeAndDecrypt(nonceEnc.getAsString());
            json.addProperty(FIELD_NONCE, new String(decrypted, StandardCharsets.UTF_8));
        }

        JsonElement ephemeralKeyEnc = json.remove(FIELD_EPHEMERAL_KEY + ENC_SUFFIX);
        if (ephemeralKeyEnc != null) {
            byte[] decrypted = CryptoUtil.getDefaultCryptoUtil()
                    .base64DecodeAndDecrypt(ephemeralKeyEnc.getAsString());
            json.addProperty(FIELD_EPHEMERAL_KEY, new String(decrypted, StandardCharsets.UTF_8));
        }

        return GSON.fromJson(json, VPFlowSession.class);
    }
}
