package app.sprout.identity.config;

import app.sprout.identity.domain.SecretBox;
import app.sprout.identity.domain.TokenService;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class IdentityBeans {

    /** Injected everywhere time matters, so tests can move it forward. */
    @Bean
    @ConditionalOnMissingBean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    SecretBox secretBox(IdentityProperties props) {
        return new SecretBox(props.totpEncryptionKey());
    }

    @Bean
    TokenService tokenService(IdentityProperties props, Clock clock) {
        return new TokenService(props, clock);
    }
}
