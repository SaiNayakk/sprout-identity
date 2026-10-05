package app.sprout.identity;

import static com.atlassian.oai.validator.mockmvc.OpenApiValidationMatchers.openApi;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import app.sprout.contracts.Contracts;
import app.sprout.identity.domain.Totp;
import com.atlassian.oai.validator.OpenApiInteractionValidator;
import com.atlassian.oai.validator.report.LevelResolver;
import com.atlassian.oai.validator.report.ValidationReport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * The identity contract, end to end inside the service: real Postgres, real HTTP handling, and
 * every successful response checked against identity-v1.yaml from sprout-contracts.
 */
@Testcontainers
@SpringBootTest(properties = {
        "spring.config.name=identity",
        "sprout.identity.totp-encryption-key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "sprout.identity.bcrypt-strength=4"})
@AutoConfigureMockMvc
class IdentityApiTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    @DynamicPropertySource
    static void db(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl() + "&currentSchema=identity");
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @TestConfiguration
    static class TestClock {
        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock(Instant.parse("2026-10-05T09:00:00Z"));
        }
    }

    /** Validates responses only: several tests send invalid requests on purpose. */
    static final OpenApiInteractionValidator CONTRACT = OpenApiInteractionValidator
            .createForInlineApiSpecification(Contracts.read(Contracts.IDENTITY_V1))
            .withBasePathOverride("/")
            .withLevelResolver(LevelResolver.create()
                    .withLevel("validation.request", ValidationReport.Level.IGNORE)
                    .build())
            .build();

    static final ResultMatcher MATCHES_CONTRACT = openApi().isValid(CONTRACT);

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired MutableClock clock;
    @Autowired JdbcClient db;

    String email;
    final String password = "monsoon-mango-42";

    @BeforeEach
    void freshAccount() {
        clock.set(Instant.parse("2026-10-05T09:00:00Z"));
        email = "user-" + UUID.randomUUID() + "@example.com";
    }

    // ── sign-up ──────────────────────────────────────────────────────────────

    @Test
    void signUpCreatesTheAccountAndQueuesTheRegisteredEvent() throws Exception {
        signUp(email, password).andExpect(status().isCreated()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.totpEnabled").value(false));
        String payload = db.sql("select payload from outbox where payload like ?").param("%" + email + "%")
                .query(String.class).single();
        JsonNode event = json.readTree(payload);
        assertThat(event.path("eventType").asText()).isEqualTo("identity.user.registered");
        assertThat(event.path("data").path("email").asText()).isEqualTo(email);
        assertThat(payload).doesNotContain(password);
    }

    @Test
    void demoUsersDontExistWhereTheSandboxIsOff() throws Exception {
        mvc.perform(post("/internal/v1/demo-users").header("X-Service-Key", "dev-only-service-key").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"x@sandbox.sprout.invalid\",\"password\":\"0123456789abcdefghijklmnopqrstuv\",\"displayName\":\"X\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void signUpRejectsADuplicateEmailIgnoringCase() throws Exception {
        signUp(email, password).andExpect(status().isCreated());
        signUp("  " + email.toUpperCase() + " ", password).andExpect(status().isConflict()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("EMAIL_TAKEN"));
    }

    @Test
    void signUpRejectsAWeakPassword() throws Exception {
        signUp(email, "password123").andExpect(status().isBadRequest()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("WEAK_PASSWORD"));
    }

    @Test
    void signUpRejectsUnknownFieldsBadEmailsAndBrokenJson() throws Exception {
        postJson("/v1/users", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\",\"displayName\":\"A\",\"isAdmin\":true}")
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        postJson("/v1/users", "{\"email\":\"not-an-email\",\"password\":\"" + password + "\",\"displayName\":\"A\"}")
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        postJson("/v1/users", "{\"email\":").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    // ── sign-in and lockout ──────────────────────────────────────────────────

    @Test
    void signInWithoutTwoFactorReturnsTokensThatWork() throws Exception {
        signUp(email, password);
        JsonNode tokens = signIn(email, password).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.tokens.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.tokens.expiresIn").value(900))
                .andReturn().getResponse().getContentAsString().transform(this::read).path("tokens");
        me(tokens.path("accessToken").asText()).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.email").value(email));
    }

    @Test
    void wrongPasswordAndUnknownEmailLookTheSame() throws Exception {
        signUp(email, password);
        signIn(email, "wrong-password-1").andExpect(status().isUnauthorized()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        signIn("nobody-" + email, password).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    void fiveWrongPasswordsLockTheAccountForFifteenMinutes() throws Exception {
        signUp(email, password);
        for (int i = 1; i <= 4; i++) {
            signIn(email, "wrong-password-" + i).andExpect(status().isUnauthorized());
        }
        signIn(email, "wrong-password-5").andExpect(status().isLocked()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.retryAfterSeconds").value(900))
                .andExpect(header().string("Retry-After", "900"));
        // even the right password is refused while locked
        signIn(email, password).andExpect(status().isLocked());
        clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        signIn(email, password).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("AUTHENTICATED"));
    }

    @Test
    void aSuccessfulSignInResetsTheFailureCount() throws Exception {
        signUp(email, password);
        for (int i = 1; i <= 4; i++) {
            signIn(email, "wrong-password-" + i).andExpect(status().isUnauthorized());
        }
        signIn(email, password).andExpect(status().isOk());
        signIn(email, "wrong-password-again").andExpect(status().isUnauthorized());
    }

    // ── two-factor ───────────────────────────────────────────────────────────

    @Test
    void twoFactorEnrollmentThenSignInNeedsTheCode() throws Exception {
        String secret = enableTotp();
        JsonNode challenge = read(signIn(email, password).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.status").value("TOTP_REQUIRED"))
                .andExpect(jsonPath("$.tokens").doesNotExist())
                .andReturn().getResponse().getContentAsString());
        String id = challenge.path("challengeId").asText();

        totp(id, wrongCode(secret)).andExpect(status().isUnauthorized()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("INVALID_TOTP"));
        totp(id, code(secret)).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.tokens.accessToken").isNotEmpty());
        // the challenge is single use
        totp(id, code(secret)).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("CHALLENGE_EXPIRED"));
    }

    @Test
    void aTwoFactorCodeCannotBeReplayedOnANewSignIn() throws Exception {
        String secret = enableTotp();
        String first = challengeId();
        String usedCode = code(secret);
        totp(first, usedCode).andExpect(status().isOk());
        totp(challengeId(), usedCode).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOTP"));
        clock.advance(Duration.ofSeconds(30));
        totp(challengeId(), code(secret)).andExpect(status().isOk());
    }

    @Test
    void aTwoFactorChallengeExpiresAfterFiveMinutes() throws Exception {
        String secret = enableTotp();
        String id = challengeId();
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        totp(id, code(secret)).andExpect(status().isUnauthorized()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("CHALLENGE_EXPIRED"));
    }

    @Test
    void wrongTwoFactorCodesCountTowardsTheLockout() throws Exception {
        String secret = enableTotp();
        String id = challengeId();
        for (int i = 1; i <= 4; i++) {
            totp(id, wrongCode(secret)).andExpect(status().isUnauthorized());
        }
        totp(id, wrongCode(secret)).andExpect(status().isLocked()).andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
    }

    @Test
    void twoFactorSetupEdgeCases() throws Exception {
        signUp(email, password);
        String access = accessToken();
        postJson("/v1/users/me/totp/confirm", "{\"code\":\"123456\"}", access).andExpect(status().isConflict())
                .andExpect(MATCHES_CONTRACT).andExpect(jsonPath("$.code").value("TOTP_NOT_STARTED"));
        JsonNode enrollment = read(postJson("/v1/users/me/totp", "", access).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.otpauthUri").value(org.hamcrest.Matchers.startsWith("otpauth://totp/Sprout:")))
                .andReturn().getResponse().getContentAsString());
        String secret = enrollment.path("secret").asText();
        postJson("/v1/users/me/totp/confirm", "{\"code\":\"" + wrongCode(secret) + "\"}", access)
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOTP"));
        postJson("/v1/users/me/totp/confirm", "{\"code\":\"" + code(secret) + "\"}", access).andExpect(status().isNoContent());
        postJson("/v1/users/me/totp", "", access).andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("TOTP_ALREADY_ENABLED"));
        String stored = db.sql("select totp_secret from users where email_normalized = ?").param(email).query(String.class).single();
        assertThat(stored).isNotEqualTo(secret).doesNotContain(secret);
    }

    // ── tokens ───────────────────────────────────────────────────────────────

    @Test
    void refreshRotatesAndASpentTokenEndsTheSession() throws Exception {
        signUp(email, password);
        JsonNode first = tokens();
        JsonNode second = read(refresh(first.path("refreshToken").asText()).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andReturn().getResponse().getContentAsString());
        assertThat(second.path("refreshToken").asText()).isNotEqualTo(first.path("refreshToken").asText());

        // the old token comes back: treat as theft, revoke the session
        refresh(first.path("refreshToken").asText()).andExpect(status().isUnauthorized()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_REUSED"));
        // the newer token was never used, but its session is gone now
        refresh(second.path("refreshToken").asText()).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
        me(second.path("accessToken").asText()).andExpect(status().isUnauthorized());
    }

    @Test
    void twoRefreshesRacingWithOneTokenCannotBothWin() throws Exception {
        signUp(email, password);
        String token = tokens().path("refreshToken").asText();
        CountDownLatch start = new CountDownLatch(1);
        Callable<Integer> attempt = () -> {
            start.await();
            return refresh(token).andReturn().getResponse().getStatus();
        };
        var pool = Executors.newFixedThreadPool(2);
        List<Future<Integer>> results = new ArrayList<>(List.of(pool.submit(attempt), pool.submit(attempt)));
        start.countDown();
        List<Integer> statuses = new ArrayList<>();
        for (Future<Integer> f : results) {
            statuses.add(f.get());
        }
        pool.shutdown();
        assertThat(statuses).containsOnlyOnce(200);
    }

    @Test
    void signOutEndsTheSession() throws Exception {
        signUp(email, password);
        JsonNode t = tokens();
        mvc.perform(delete("/v1/sessions/current").header("Authorization", "Bearer " + t.path("accessToken").asText()))
                .andExpect(status().isNoContent());
        me(t.path("accessToken").asText()).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        refresh(t.path("refreshToken").asText()).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    void accessTokensAreCheckedForPresenceSignatureAndExpiry() throws Exception {
        mvc.perform(get("/v1/users/me")).andExpect(status().isUnauthorized()).andExpect(MATCHES_CONTRACT);
        me("not.a.jwt").andExpect(status().isUnauthorized());
        signUp(email, password);
        String access = accessToken();
        String tampered = access.substring(0, access.length() - 4) + (access.endsWith("AAAA") ? "BBBB" : "AAAA");
        me(tampered).andExpect(status().isUnauthorized());
        clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        me(access).andExpect(status().isUnauthorized());
    }

    @Test
    void unknownRefreshTokenIsRejected() throws Exception {
        refresh("made-up-token").andExpect(status().isUnauthorized()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    void jwksPublishesTheVerificationKey() throws Exception {
        mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    void errorsCarryTheRequestId() throws Exception {
        mvc.perform(get("/v1/users/me").header("X-Request-Id", "trace-123"))
                .andExpect(header().string("X-Request-Id", "trace-123"))
                .andExpect(jsonPath("$.requestId").value("trace-123"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    ResultActions signUp(String email, String password) throws Exception {
        return postJson("/v1/users", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\",\"displayName\":\"Asha\"}");
    }

    ResultActions signIn(String email, String password) throws Exception {
        return postJson("/v1/sessions", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}");
    }

    ResultActions totp(String challengeId, String code) throws Exception {
        return postJson("/v1/sessions/totp", "{\"challengeId\":\"" + challengeId + "\",\"code\":\"" + code + "\"}");
    }

    ResultActions refresh(String token) throws Exception {
        return postJson("/v1/tokens/refresh", "{\"refreshToken\":\"" + token + "\"}");
    }

    ResultActions me(String accessToken) throws Exception {
        return mvc.perform(get("/v1/users/me").header("Authorization", "Bearer " + accessToken));
    }

    ResultActions postJson(String path, String body) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    ResultActions postJson(String path, String body, String accessToken) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body)
                .header("Authorization", "Bearer " + accessToken));
    }

    JsonNode tokens() throws Exception {
        return read(signIn(email, password).andReturn().getResponse().getContentAsString()).path("tokens");
    }

    String accessToken() throws Exception {
        return tokens().path("accessToken").asText();
    }

    String challengeId() throws Exception {
        return read(signIn(email, password).andExpect(jsonPath("$.status").value("TOTP_REQUIRED"))
                .andReturn().getResponse().getContentAsString()).path("challengeId").asText();
    }

    /** Signs up, enrolls and confirms two-factor; returns the secret. */
    String enableTotp() throws Exception {
        signUp(email, password);
        String access = accessToken();
        String secret = read(postJson("/v1/users/me/totp", "", access).andReturn().getResponse().getContentAsString())
                .path("secret").asText();
        postJson("/v1/users/me/totp/confirm", "{\"code\":\"" + code(secret) + "\"}", access).andExpect(status().isNoContent());
        // the code that confirmed setup can't be reused, so sign-ins in these tests use the next one
        clock.advance(Duration.ofSeconds(30));
        return secret;
    }

    String code(String secret) {
        return Totp.code(secret, Totp.step(clock.instant()));
    }

    String wrongCode(String secret) {
        String right = code(secret);
        String candidate = right.equals("000000") ? "111111" : "000000";
        // make sure the "wrong" code isn't valid for an adjacent step either
        long step = Totp.step(clock.instant());
        while (candidate.equals(Totp.code(secret, step - 1)) || candidate.equals(Totp.code(secret, step + 1)) || candidate.equals(right)) {
            candidate = String.format("%06d", (Integer.parseInt(candidate) + 111111) % 1_000_000);
        }
        return candidate;
    }

    JsonNode read(String body) {
        try {
            return json.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
