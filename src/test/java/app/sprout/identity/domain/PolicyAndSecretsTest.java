package app.sprout.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class PolicyAndSecretsTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void acceptsALongUncommonPassword() {
        PasswordPolicy.check("monsoon-mango-42", "asha@example.com");
    }

    @Test
    void rejectsShortCommonRepetitiveOrEmailBasedPasswords() {
        for (String weak : new String[] {"short1", "password123", "Password123", "aaaaaaaaaaaa", "ababababab", "my-asha-password"}) {
            assertThatThrownBy(() -> PasswordPolicy.check(weak, "asha@example.com"))
                    .as(weak).isInstanceOf(IdentityException.class)
                    .extracting(e -> ((IdentityException) e).code()).isEqualTo(ErrorCode.WEAK_PASSWORD);
        }
        assertThatThrownBy(() -> PasswordPolicy.check("x".repeat(129), null)).isInstanceOf(IdentityException.class);
    }

    @Test
    void secretBoxRoundTripsAndUsesAFreshIvEachTime() {
        SecretBox box = new SecretBox(KEY);
        String a = box.seal("JBSWY3DPEHPK3PXP");
        String b = box.seal("JBSWY3DPEHPK3PXP");
        assertThat(a).isNotEqualTo(b);
        assertThat(box.open(a)).isEqualTo("JBSWY3DPEHPK3PXP");
    }

    @Test
    void secretBoxDetectsTamperingAndWrongKeys() {
        String sealed = new SecretBox(KEY).seal("secret");
        byte[] raw = Base64.getDecoder().decode(sealed);
        raw[raw.length - 1] ^= 1;
        assertThatThrownBy(() -> new SecretBox(KEY).open(Base64.getEncoder().encodeToString(raw)))
                .isInstanceOf(IllegalStateException.class);
        byte[] other = new byte[32];
        other[0] = 1;
        assertThatThrownBy(() -> new SecretBox(Base64.getEncoder().encodeToString(other)).open(sealed))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void secretBoxRefusesAMissingOrShortKey() {
        assertThatThrownBy(() -> new SecretBox("")).hasMessageContaining("IDENTITY_TOTP_KEY");
        assertThatThrownBy(() -> new SecretBox(Base64.getEncoder().encodeToString(new byte[16]))).hasMessageContaining("32 bytes");
    }
}
