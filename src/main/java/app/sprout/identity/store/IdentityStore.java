package app.sprout.identity.store;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** All SQL for the identity schema. Plain JDBC: every query is visible and explicit. */
@Repository
public class IdentityStore {

    private final JdbcClient db;

    public IdentityStore(JdbcClient db) {
        this.db = db;
    }

    public record UserRow(
            UUID id, String email, String displayName, String passwordHash,
            String totpSecret, String totpPendingSecret, Long totpLastStep,
            int failedAttempts, Instant lockedUntil, Instant createdAt, boolean demo) {
        public boolean totpEnabled() {
            return totpSecret != null;
        }
    }

    public record RefreshRow(UUID sessionId, Instant expiresAt, Instant usedAt, Instant sessionRevokedAt,
                             Instant sessionExpiresAt, UUID userId) {}

    public record ChallengeRow(String id, UUID userId, Instant expiresAt, Instant usedAt, int attempts) {}

    // ── users ────────────────────────────────────────────────────────────────

    public boolean emailExists(String normalized) {
        return db.sql("select count(*) from users where email_normalized = ?").param(normalized)
                .query(Long.class).single() > 0;
    }

    public void insertUser(UUID id, String email, String normalized, String displayName, String hash, Instant now) {
        db.sql("""
                insert into users (id, email, email_normalized, display_name, password_hash, created_at)
                values (?, ?, ?, ?, ?, ?)""")
                .params(id, email, normalized, displayName, hash, ts(now)).update();
    }

    /** Creates a demo user, or (same email) makes it one with this password and name. */
    public UUID upsertDemoUser(UUID id, String email, String normalized, String displayName, String hash, Instant now) {
        return db.sql("""
                insert into users (id, email, email_normalized, display_name, password_hash, created_at, demo)
                values (?, ?, ?, ?, ?, ?, true)
                on conflict (email_normalized) do update set display_name = excluded.display_name, password_hash = excluded.password_hash,
                    demo = true, failed_attempts = 0, locked_until = null
                returning id""")
                .params(id, email, normalized, displayName, hash, ts(now)).query(UUID.class).single();
    }

    public Optional<UserRow> findUserByEmail(String normalized) {
        return db.sql("select * from users where email_normalized = ?").param(normalized)
                .query(IdentityStore::user).optional();
    }

    public Optional<UserRow> findUser(UUID id) {
        return db.sql("select * from users where id = ?").param(id).query(IdentityStore::user).optional();
    }

    /** Locks the row for the rest of the transaction, so concurrent sign-ins count attempts correctly. */
    public Optional<UserRow> lockUser(UUID id) {
        return db.sql("select * from users where id = ? for update").param(id).query(IdentityStore::user).optional();
    }

    public void recordFailure(UUID id, int failedAttempts, Instant lockedUntil) {
        db.sql("update users set failed_attempts = ?, locked_until = ? where id = ?")
                .params(failedAttempts, ts(lockedUntil), id).update();
    }

    public void clearFailures(UUID id) {
        db.sql("update users set failed_attempts = 0, locked_until = null where id = ?").param(id).update();
    }

    public void setPendingTotp(UUID id, String sealedSecret) {
        db.sql("update users set totp_pending_secret = ? where id = ?").params(sealedSecret, id).update();
    }

    public void confirmTotp(UUID id, long step) {
        db.sql("update users set totp_secret = totp_pending_secret, totp_pending_secret = null, totp_last_step = ? where id = ?")
                .params(step, id).update();
    }

    public void setTotpLastStep(UUID id, long step) {
        db.sql("update users set totp_last_step = ? where id = ?").params(step, id).update();
    }

    // ── sessions and refresh tokens ──────────────────────────────────────────

    public void insertSession(UUID id, UUID userId, Instant now, Instant expiresAt) {
        db.sql("insert into sessions (id, user_id, created_at, expires_at) values (?, ?, ?, ?)")
                .params(id, userId, ts(now), ts(expiresAt)).update();
    }

    public boolean sessionActive(UUID sessionId, Instant now) {
        return db.sql("select count(*) from sessions where id = ? and revoked_at is null and expires_at > ?")
                .params(sessionId, ts(now)).query(Long.class).single() > 0;
    }

    public void revokeSession(UUID sessionId, String reason, Instant now) {
        db.sql("update sessions set revoked_at = ?, revoke_reason = ? where id = ? and revoked_at is null")
                .params(ts(now), reason, sessionId).update();
    }

    public void insertRefreshToken(String hash, UUID sessionId, Instant now, Instant expiresAt) {
        db.sql("insert into refresh_tokens (token_hash, session_id, created_at, expires_at) values (?, ?, ?, ?)")
                .params(hash, sessionId, ts(now), ts(expiresAt)).update();
    }

    public Optional<RefreshRow> findRefresh(String hash) {
        return db.sql("""
                select r.session_id, r.expires_at, r.used_at, s.revoked_at, s.expires_at as session_expires_at, s.user_id
                from refresh_tokens r join sessions s on s.id = r.session_id
                where r.token_hash = ?""").param(hash)
                .query((rs, n) -> new RefreshRow(rs.getObject("session_id", UUID.class), inst(rs, "expires_at"),
                        inst(rs, "used_at"), inst(rs, "revoked_at"), inst(rs, "session_expires_at"),
                        rs.getObject("user_id", UUID.class)))
                .optional();
    }

    /**
     * Marks a refresh token used, atomically. Returns false if it was already used: two requests
     * racing with the same token can't both win, and the loser is treated as reuse.
     */
    public boolean markRefreshUsed(String hash, Instant now) {
        return db.sql("update refresh_tokens set used_at = ? where token_hash = ? and used_at is null")
                .params(ts(now), hash).update() == 1;
    }

    // ── two-factor challenges ───────────────────────────────────────────────

    public void insertChallenge(String id, UUID userId, Instant now, Instant expiresAt) {
        db.sql("insert into totp_challenges (id, user_id, created_at, expires_at) values (?, ?, ?, ?)")
                .params(id, userId, ts(now), ts(expiresAt)).update();
    }

    public Optional<ChallengeRow> lockChallenge(String id) {
        return db.sql("select * from totp_challenges where id = ? for update").param(id)
                .query((rs, n) -> new ChallengeRow(rs.getString("id"), rs.getObject("user_id", UUID.class),
                        inst(rs, "expires_at"), inst(rs, "used_at"), rs.getInt("attempts")))
                .optional();
    }

    public void challengeAttempt(String id, int attempts, boolean burn, Instant now) {
        db.sql("update totp_challenges set attempts = ?, used_at = case when ? then ? else used_at end where id = ?")
                .params(attempts, burn, ts(now), id).update();
    }

    public void useChallenge(String id, Instant now) {
        db.sql("update totp_challenges set used_at = ? where id = ?").params(ts(now), id).update();
    }

    // ── outbox ───────────────────────────────────────────────────────────────

    public void insertOutbox(UUID id, String eventType, String payload, Instant now) {
        db.sql("insert into outbox (id, event_type, payload, created_at) values (?, ?, ?, ?)")
                .params(id, eventType, payload, ts(now)).update();
    }

    public long unpublishedEvents() {
        return db.sql("select count(*) from outbox where published_at is null").query(Long.class).single();
    }

    // ── mapping ──────────────────────────────────────────────────────────────

    private static UserRow user(ResultSet rs, int n) throws SQLException {
        return new UserRow(rs.getObject("id", UUID.class), rs.getString("email"), rs.getString("display_name"),
                rs.getString("password_hash"), rs.getString("totp_secret"), rs.getString("totp_pending_secret"),
                rs.getObject("totp_last_step", Long.class), rs.getInt("failed_attempts"),
                inst(rs, "locked_until"), inst(rs, "created_at"), rs.getBoolean("demo"));
    }

    private static Instant inst(ResultSet rs, String col) throws SQLException {
        Timestamp t = rs.getTimestamp(col);
        return t == null ? null : t.toInstant();
    }

    private static Timestamp ts(Instant i) {
        return i == null ? null : Timestamp.from(i);
    }
}
