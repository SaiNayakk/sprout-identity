package app.sprout.identity;

import static com.atlassian.oai.validator.mockmvc.OpenApiValidationMatchers.openApi;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import app.sprout.contracts.Contracts;
import com.atlassian.oai.validator.OpenApiInteractionValidator;
import com.atlassian.oai.validator.report.LevelResolver;
import com.atlassian.oai.validator.report.ValidationReport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Demo users, where the sandbox is switched on: made by the sandbox, signed in like anyone, impossible to spoil. */
@Testcontainers
@SpringBootTest(properties = {
        "spring.config.name=identity",
        "sprout.identity.totp-encryption-key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "sprout.identity.bcrypt-strength=4",
        "sprout.identity.demo.enabled=true"})
@AutoConfigureMockMvc
class DemoUsersTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    @DynamicPropertySource
    static void db(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl() + "&currentSchema=identity");
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
    }

    static final OpenApiInteractionValidator CONTRACT = OpenApiInteractionValidator
            .createForInlineApiSpecification(Contracts.read(Contracts.IDENTITY_V1))
            .withBasePathOverride("/")
            .withLevelResolver(LevelResolver.create().withLevel("validation.request", ValidationReport.Level.IGNORE).build())
            .build();
    static final ResultMatcher MATCHES_CONTRACT = openApi().isValid(CONTRACT);
    static final String KEY = "dev-only-service-key";
    static final String PASSWORD = "0123456789abcdefghijklmnopqrstuv";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    ResultActions post(String path, Object body, Map<String, String> headers) throws Exception {
        var req = org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(path).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(body));
        headers.forEach(req::header);
        return mvc.perform(req);
    }

    ResultActions demoUser(String email, String password, String name) throws Exception {
        return post("/internal/v1/demo-users", Map.of("email", email, "password", password, "displayName", name), Map.of("X-Service-Key", KEY));
    }

    ResultActions signIn(String email, String password) throws Exception {
        return post("/v1/sessions", Map.of("email", email, "password", password), Map.of());
    }

    @Test
    void theSandboxMakesADemoUserWhoSignsInLikeAnyone() throws Exception {
        String email = "meera-" + UUID.randomUUID() + "@sandbox.sprout.invalid";
        JsonNode u = json.readTree(demoUser(email, PASSWORD, "Meera Iyer").andExpect(status().isOk()).andExpect(MATCHES_CONTRACT)
                .andReturn().getResponse().getContentAsString());
        demoUser(email, PASSWORD + "x", "Meera Iyer").andExpect(status().isOk()).andExpect(jsonPath("$.id").value(u.path("id").asText()));
        signIn(email, PASSWORD + "x").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("AUTHENTICATED"));
        post("/internal/v1/demo-users", Map.of("email", email, "password", PASSWORD, "displayName", "x"), Map.of()).andExpect(status().isUnauthorized());
        demoUser("short@sandbox.sprout.invalid", "too-short", "Ari").andExpect(status().isBadRequest());
    }

    @Test
    void aDemoUserNeverLocksAndCantTurnOnTwoFactor() throws Exception {
        String email = "kiran-" + UUID.randomUUID() + "@sandbox.sprout.invalid";
        demoUser(email, PASSWORD, "Kiran Joshi").andExpect(status().isOk());
        for (int i = 0; i < 8; i++) {
            signIn(email, "wrong-guess-" + i).andExpect(status().isUnauthorized());
        }
        JsonNode in = json.readTree(signIn(email, PASSWORD).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        String access = in.path("tokens").path("accessToken").asText();
        assertThat(access).isNotBlank();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/v1/users/me/totp")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isBadRequest()).andExpect(MATCHES_CONTRACT).andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }
}
