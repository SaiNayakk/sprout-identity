package app.sprout.identity.domain;

import app.sprout.identity.config.IdentityProperties;
import app.sprout.identity.store.IdentityStore;
import app.sprout.identity.store.IdentityStore.ChallengeRow;
import app.sprout.identity.store.IdentityStore.RefreshRow;
import app.sprout.identity.store.IdentityStore.UserRow;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Accounts, sign-in, two-factor and tokens. Every rule here is written down in the identity contract. */
@Service
public class IdentityService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final IdentityStore store;
    private final TokenService tokens;
    private final SecretBox secrets;
    private final IdentityProperties props;
    private final Clock clock;
    private final MeterRegistry meters;
    private final ObjectMapper json;
    private final BCryptPasswordEncoder bcrypt;
    /** Checked against when the email is unknown, so a miss takes as long as a wrong password. */
    private final String dummyHash;

    public IdentityService(IdentityStore store, TokenService tokens, SecretBox secrets, IdentityProperties props,
                           Clock clock, MeterRegistry meters, ObjectMapper json) {
        this.store = store;
        this.tokens = tokens;
        this.secrets = secrets;
        this.props = props;
        this.clock = clock;
        this.meters = meters;
        this.json = json;
        this.bcrypt = new BCryptPasswordEncoder(props.bcryptStrength());
        this.dummyHash = bcrypt.encode("not-a-real-password-" + UUID.randomUUID());
    }

    public record TokenPair(String accessToken, String tokenType, long expiresIn, String refreshToken) {}

    /** AUTHENTICATED with tokens, or TOTP_REQUIRED with a challenge. */
    public record SignInResult(String status, TokenPair tokens, String challengeId, Instant challengeExpiresAt) {
        static SignInResult authenticated(TokenPair t) {
            return new SignInResult("AUTHENTICATED", t, null, null);
        }

        static SignInResult totpRequired(String id, Instant expiresAt) {
            return new SignInResult("TOTP_REQUIRED", null, id, expiresAt);
        }
    }

    public record Enrollment(String secret, String otpauthUri) {}

    // ── sign-up ──────────────────────────────────────────────────────────────

    @Transactional
    public UserRow signUp(String email, String password, String displayName) {
        String normalized = normalize(email);
        PasswordPolicy.check(password, normalized);
        if (store.emailExists(normalized)) {
            meters.counter("identity.signups", "result", "email_taken").increment();
            throw new IdentityException(ErrorCode.EMAIL_TAKEN, "Sign in instead, or use a different email.");
        }
        Instant now = clock.instant();
        UUID id = UUID.randomUUID();
        store.insertUser(id, email.trim(), normalized, displayName.trim(), bcrypt.encode(password), now);
        store.insertOutbox(UUID.randomUUID(), "identity.user.registered", userRegistered(id, normalized, displayName.trim(), now), now);
        meters.counter("identity.signups", "result", "created").increment();
        return store.findUser(id).orElseThrow();
    }

    // ── sign-in ──────────────────────────────────────────────────────────────

    @Transactional(noRollbackFor = IdentityException.class)
    public SignInResult signIn(String email, String password) {
        Instant now = clock.instant();
        var found = store.findUserByEmail(normalize(email));
        if (found.isEmpty()) {
            bcrypt.matches(password, dummyHash);
            meters.counter("identity.signins", "result", "invalid").increment();
            throw invalidCredentials();
        }
        UserRow user = store.lockUser(found.get().id()).orElseThrow();
        ensureNotLocked(user, now);
        if (!bcrypt.matches(password, user.passwordHash())) {
            registerFailure(user, now);
            meters.counter("identity.signins", "result", "invalid").increment();
            throw invalidCredentials();
        }
        store.clearFailures(user.id());
        if (user.totpEnabled()) {
            String challengeId = randomToken(24);
            Instant expires = now.plus(props.challengeTtl());
            store.insertChallenge(challengeId, user.id(), now, expires);
            meters.counter("identity.signins", "result", "totp_required").increment();
            return SignInResult.totpRequired(challengeId, expires);
        }
        meters.counter("identity.signins", "result", "authenticated").increment();
        return SignInResult.authenticated(openSession(user.id(), now));
    }

    @Transactional(noRollbackFor = IdentityException.class)
    public SignInResult completeTotp(String challengeId, String code) {
        Instant now = clock.instant();
        ChallengeRow challenge = store.lockChallenge(challengeId)
                .filter(c -> c.usedAt() == null && c.expiresAt().isAfter(now))
                .orElseThrow(() -> new IdentityException(ErrorCode.CHALLENGE_EXPIRED, "Sign in with your password again."));
        UserRow user = store.lockUser(challenge.userId()).orElseThrow();
        ensureNotLocked(user, now);
        long step = Totp.verify(secrets.open(user.totpSecret()), code, now, user.totpLastStep());
        if (step < 0) {
            int attempts = challenge.attempts() + 1;
            store.challengeAttempt(challengeId, attempts, attempts >= props.maxFailedAttempts(), now);
            registerFailure(user, now);
            meters.counter("identity.signins", "result", "invalid_totp").increment();
            throw new IdentityException(ErrorCode.INVALID_TOTP, "Check your authenticator app and try the latest code.");
        }
        store.useChallenge(challengeId, now);
        store.setTotpLastStep(user.id(), step);
        store.clearFailures(user.id());
        meters.counter("identity.signins", "result", "authenticated").increment();
        return SignInResult.authenticated(openSession(user.id(), now));
    }

    // ── tokens ───────────────────────────────────────────────────────────────

    @Transactional(noRollbackFor = IdentityException.class)
    public TokenPair refresh(String refreshToken) {
        Instant now = clock.instant();
        String hash = sha256(refreshToken);
        RefreshRow row = store.findRefresh(hash).orElseThrow(IdentityService::invalidRefresh);
        if (row.usedAt() != null || !store.markRefreshUsed(hash, now)) {
            // A spent token came back: someone else may hold a copy. End the whole session.
            store.revokeSession(row.sessionId(), "refresh_reuse", now);
            meters.counter("identity.refresh", "result", "reused").increment();
            throw new IdentityException(ErrorCode.REFRESH_TOKEN_REUSED,
                    "This sign-in was ended because an old token was used again. Sign in again.");
        }
        if (row.sessionRevokedAt() != null || !row.expiresAt().isAfter(now) || !row.sessionExpiresAt().isAfter(now)) {
            meters.counter("identity.refresh", "result", "invalid").increment();
            throw invalidRefresh();
        }
        meters.counter("identity.refresh", "result", "rotated").increment();
        return issuePair(row.userId(), row.sessionId(), now);
    }

    /** The signed-in user, or UNAUTHENTICATED. Checks the token and that its session wasn't ended. */
    @Transactional(readOnly = true)
    public TokenService.AccessClaims authenticate(String accessToken) {
        TokenService.AccessClaims claims = tokens.verify(accessToken);
        if (!store.sessionActive(claims.sessionId(), clock.instant())) {
            throw new IdentityException(ErrorCode.UNAUTHENTICATED, "You signed out. Sign in again.");
        }
        return claims;
    }

    @Transactional
    public void signOut(TokenService.AccessClaims claims) {
        store.revokeSession(claims.sessionId(), "signed_out", clock.instant());
        meters.counter("identity.signouts").increment();
    }

    @Transactional(readOnly = true)
    public UserRow user(java.util.UUID id) {
        return store.findUser(id).orElseThrow(() -> new IdentityException(ErrorCode.UNAUTHENTICATED, "Sign in again."));
    }

    // ── two-factor setup ─────────────────────────────────────────────────────

    @Transactional
    public Enrollment startTotp(UUID userId) {
        UserRow user = store.lockUser(userId).orElseThrow();
        if (user.totpEnabled()) {
            throw new IdentityException(ErrorCode.TOTP_ALREADY_ENABLED, "Turn two-factor off first to set it up again.");
        }
        String secret = Totp.newSecret();
        store.setPendingTotp(userId, secrets.seal(secret));
        return new Enrollment(secret, Totp.otpauthUri("Sprout", user.email(), secret));
    }

    @Transactional
    public void confirmTotp(UUID userId, String code) {
        UserRow user = store.lockUser(userId).orElseThrow();
        if (user.totpEnabled()) {
            throw new IdentityException(ErrorCode.TOTP_ALREADY_ENABLED, "Two-factor is already on.");
        }
        if (user.totpPendingSecret() == null) {
            throw new IdentityException(ErrorCode.TOTP_NOT_STARTED, "Start two-factor setup first.");
        }
        long step = Totp.verify(secrets.open(user.totpPendingSecret()), code, clock.instant(), null);
        if (step < 0) {
            throw new IdentityException(ErrorCode.INVALID_TOTP, "Check your authenticator app and try the latest code.");
        }
        store.confirmTotp(userId, step);
        meters.counter("identity.totp_enabled").increment();
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private TokenPair openSession(UUID userId, Instant now) {
        UUID sessionId = UUID.randomUUID();
        store.insertSession(sessionId, userId, now, now.plus(props.refreshTokenTtl()));
        return issuePair(userId, sessionId, now);
    }

    private TokenPair issuePair(UUID userId, UUID sessionId, Instant now) {
        String refresh = randomToken(32);
        store.insertRefreshToken(sha256(refresh), sessionId, now, now.plus(props.refreshTokenTtl()));
        return new TokenPair(tokens.issueAccessToken(userId, sessionId), "Bearer", tokens.accessTokenTtlSeconds(), refresh);
    }

    private void ensureNotLocked(UserRow user, Instant now) {
        if (user.lockedUntil() != null && user.lockedUntil().isAfter(now)) {
            long wait = Math.max(1, Duration.between(now, user.lockedUntil()).toSeconds());
            meters.counter("identity.signins", "result", "locked").increment();
            throw new IdentityException(ErrorCode.ACCOUNT_LOCKED,
                    "Too many attempts. Try again in " + Math.max(1, (wait + 59) / 60) + " minutes.", wait);
        }
    }

    /** Counts a failure; the attempt that reaches the limit locks the account and says so. */
    private void registerFailure(UserRow user, Instant now) {
        int failures = user.failedAttempts() + 1;
        if (failures >= props.maxFailedAttempts()) {
            Instant until = now.plus(props.lockout());
            store.recordFailure(user.id(), 0, until);
            meters.counter("identity.lockouts").increment();
            throw new IdentityException(ErrorCode.ACCOUNT_LOCKED,
                    "Too many attempts. Try again in " + props.lockout().toMinutes() + " minutes.", props.lockout().toSeconds());
        }
        store.recordFailure(user.id(), failures, null);
    }

    private String userRegistered(UUID userId, String email, String displayName, Instant now) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventId", UUID.randomUUID().toString());
        event.put("eventType", "identity.user.registered");
        event.put("eventVersion", 1);
        event.put("occurredAt", now.toString());
        event.put("producer", "sprout-identity");
        String requestId = MDC.get("requestId");
        if (requestId != null) {
            event.put("correlationId", requestId);
        }
        event.put("data", Map.of("userId", userId.toString(), "email", email, "displayName", displayName));
        try {
            return json.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String randomToken(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static IdentityException invalidCredentials() {
        return new IdentityException(ErrorCode.INVALID_CREDENTIALS, "Check your email and password and try again.");
    }

    private static IdentityException invalidRefresh() {
        return new IdentityException(ErrorCode.INVALID_REFRESH_TOKEN, "Sign in again.");
    }
}
