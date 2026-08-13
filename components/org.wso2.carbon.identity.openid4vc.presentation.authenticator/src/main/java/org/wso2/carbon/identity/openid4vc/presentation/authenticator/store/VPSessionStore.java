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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.openid4vc.presentation.authenticator.model.VPFlowSession;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * JDBC-backed persistence store for {@link VPFlowSession} objects.
 *
 * <p>Writes to the dedicated {@code IDN_VP_SESSION_STORE} table so VP sessions are
 * visible across all cluster nodes.
 * {@link org.wso2.carbon.identity.openid4vc.presentation.authenticator.cache.VPSessionCache}
 * consults this store on a local-cache miss, giving each pod an eventual-consistency
 * view of every active VP flow regardless of which pod initiated it.</p>
 */
public class VPSessionStore {

    private static final Log LOG = LogFactory.getLog(VPSessionStore.class);

    private static final String TABLE = "IDN_VP_SESSION_STORE";

    private static final String SQL_INSERT =
            "INSERT INTO IDN_VP_SESSION_STORE (SESSION_ID, SESSION_DATA, CREATED_AT, EXPIRES_AT, POLL_TOKEN) " +
            "VALUES (?, ?, ?, ?, ?)";

    private static final String SQL_UPDATE =
            "UPDATE IDN_VP_SESSION_STORE SET SESSION_DATA = ?, EXPIRES_AT = ? WHERE SESSION_ID = ?";

    private static final String SQL_SELECT =
            "SELECT SESSION_DATA, EXPIRES_AT FROM IDN_VP_SESSION_STORE WHERE SESSION_ID = ?";

    private static final String SQL_SELECT_BY_POLL_TOKEN =
            "SELECT SESSION_ID FROM IDN_VP_SESSION_STORE WHERE POLL_TOKEN = ?";

    private static final String SQL_DELETE =
            "DELETE FROM IDN_VP_SESSION_STORE WHERE SESSION_ID = ?";

    private static final String SQL_DELETE_EXPIRED =
            "DELETE FROM IDN_VP_SESSION_STORE WHERE EXPIRES_AT < ?";

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
     */
    public void put(String requestId, VPFlowSession session) {

        byte[] data;
        try {
            byte[] serialized = serialize(session);
            String encrypted = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(serialized);
            data = encrypted.getBytes(StandardCharsets.UTF_8);
        } catch (IOException | CryptoException e) {
            LOG.error("Failed to serialize/encrypt VP session for requestId: " + requestId, e);
            return;
        }

        Connection conn = null;
        try {
            conn = IdentityDatabaseUtil.getSessionDBConnection(true);
            if (!update(conn, requestId, data, session.getExpiresAt())) {
                insert(conn, requestId, data, session.getExpiresAt(), session.getPollToken());
            }
            IdentityDatabaseUtil.commitTransaction(conn);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(conn);
            LOG.error("Failed to persist VP session for requestId: " + requestId, e);
        } finally {
            IdentityDatabaseUtil.closeConnection(conn);
        }
    }

    /**
     * Retrieves a VP session by its request ID.
     * Returns {@code null} if the session does not exist or has expired.
     *
     * @param requestId the VP session identifier
     * @return the session, or {@code null}
     */
    public VPFlowSession get(String requestId) {

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = IdentityDatabaseUtil.getSessionDBConnection(false);
            ps = conn.prepareStatement(SQL_SELECT);
            ps.setString(1, requestId);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }
            long expiresAt = rs.getLong(2);
            if (System.currentTimeMillis() > expiresAt) {
                // Expired — clean up and treat as not found.
                IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
                conn = null;
                remove(requestId);
                return null;
            }
            String encrypted = new String(rs.getBytes(1), StandardCharsets.UTF_8);
            byte[] data = CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(encrypted);
            return deserialize(data);
        } catch (SQLException | IOException | ClassNotFoundException | CryptoException e) {
            LOG.error("Failed to retrieve VP session for requestId: " + requestId, e);
            return null;
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, rs, ps);
        }
    }

    /**
     * Deletes a VP session from the store.
     *
     * @param requestId the VP session identifier
     */
    public void remove(String requestId) {

        Connection conn = null;
        PreparedStatement ps = null;
        try {
            conn = IdentityDatabaseUtil.getSessionDBConnection(true);
            ps = conn.prepareStatement(SQL_DELETE);
            ps.setString(1, requestId);
            ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(conn);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(conn);
            LOG.error("Failed to remove VP session for requestId: " + requestId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    /**
     * Deletes all expired VP sessions. Intended for periodic cleanup tasks.
     */
    public void removeExpired() {

        Connection conn = null;
        PreparedStatement ps = null;
        try {
            conn = IdentityDatabaseUtil.getSessionDBConnection(true);
            ps = conn.prepareStatement(SQL_DELETE_EXPIRED);
            ps.setLong(1, System.currentTimeMillis());
            int deleted = ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(conn);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Removed " + deleted + " expired VP sessions from " + TABLE + ".");
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(conn);
            LOG.error("Failed to remove expired VP sessions.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, null, ps);
        }
    }

    private boolean update(Connection conn, String requestId, byte[] data, long expiresAt)
            throws SQLException {

        try (PreparedStatement ps = conn.prepareStatement(SQL_UPDATE)) {
            ps.setBytes(1, data);
            ps.setLong(2, expiresAt);
            ps.setString(3, requestId);
            return ps.executeUpdate() > 0;
        }
    }

    private void insert(Connection conn, String requestId, byte[] data, long expiresAt, String pollToken)
            throws SQLException {

        try (PreparedStatement ps = conn.prepareStatement(SQL_INSERT)) {
            ps.setString(1, requestId);
            ps.setBytes(2, data);
            ps.setLong(3, System.currentTimeMillis());
            ps.setLong(4, expiresAt);
            ps.setString(5, pollToken);
            ps.executeUpdate();
        }
    }

    /**
     * Looks up the VP session request ID associated with the given poll token.
     * Returns {@code null} if no session matches or the token has been removed.
     *
     * @param pollToken the browser-only poll token issued at session initiation
     * @return the corresponding request ID, or {@code null}
     */
    public String getRequestIdByPollToken(String pollToken) {

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = IdentityDatabaseUtil.getSessionDBConnection(false);
            ps = conn.prepareStatement(SQL_SELECT_BY_POLL_TOKEN);
            ps.setString(1, pollToken);
            rs = ps.executeQuery();
            return rs.next() ? rs.getString(1) : null;
        } catch (SQLException e) {
            LOG.error("Failed to look up VP session by pollToken.", e);
            return null;
        } finally {
            IdentityDatabaseUtil.closeAllConnections(conn, rs, ps);
        }
    }

    private static byte[] serialize(VPFlowSession session) throws IOException {

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(session);
            return bos.toByteArray();
        }
    }

    private static VPFlowSession deserialize(byte[] data)
            throws IOException, ClassNotFoundException {

        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (VPFlowSession) ois.readObject();
        }
    }
}
