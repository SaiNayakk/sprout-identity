package app.sprout.identity.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Settings under {@code sprout.identity} in identity.yml. */
@ConfigurationProperties("sprout.identity")
public record IdentityProperties(
        String issuer,
        String audience,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        Duration challengeTtl,
        int maxFailedAttempts,
        Duration lockout,
        int bcryptStrength,
        String totpEncryptionKey,
        String signingKeyPath,
        Demo demo) {

    /** Demo users for the public sandbox: only where it's switched on, created by Sprout services with this key. */
    public record Demo(boolean enabled, String serviceKey) {}
}
