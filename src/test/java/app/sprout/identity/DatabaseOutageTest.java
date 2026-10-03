package app.sprout.identity;

import static com.atlassian.oai.validator.mockmvc.OpenApiValidationMatchers.openApi;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * CHAOS-01 as a regression test: with the database gone, identity answers 503 with Retry-After
 * within a couple of seconds, instead of holding the request until the gateway times out.
 */
@Testcontainers
@SpringBootTest(properties = {
        "spring.config.name=identity",
        "sprout.identity.totp-encryption-key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "sprout.identity.bcrypt-strength=4"})
@AutoConfigureMockMvc
class DatabaseOutageTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    @DynamicPropertySource
    static void db(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl() + "&currentSchema=identity");
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired MockMvc mvc;

    @Test
    void withTheDatabaseGoneSignInFailsFastWith503() throws Exception {
        POSTGRES.stop();
        long start = System.nanoTime();
        mvc.perform(post("/v1/sessions").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"asha@example.com\",\"password\":\"monsoon-mango-42\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("UPSTREAM_UNAVAILABLE"))
                .andExpect(header().string("Retry-After", "5"))
                .andExpect(openApi().isValid(IdentityApiTest.CONTRACT));
        long millis = (System.nanoTime() - start) / 1_000_000;
        assertThat(millis).as("answered within the gateway's 5 s timeout, with room to spare").isLessThan(4_000);
    }
}
