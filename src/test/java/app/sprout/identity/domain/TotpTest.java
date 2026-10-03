package app.sprout.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TotpTest {

    /** RFC 6238 appendix B: the SHA-1 secret is the ASCII bytes "12345678901234567890". */
    private static final String RFC_SECRET = Totp.base32Encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    @ParameterizedTest(name = "t={0} -> {1}")
    @CsvSource({
            "59, 287082",          // RFC: 94287082
            "1111111109, 081804",  // RFC: 07081804
            "1111111111, 050471",  // RFC: 14050471
            "1234567890, 005924",  // RFC: 89005924
            "2000000000, 279037",  // RFC: 69279037
            "20000000000, 353130"  // RFC: 65353130
    })
    void matchesRfc6238TestVectors(long epochSeconds, String expected) {
        assertThat(Totp.code(RFC_SECRET, Totp.step(Instant.ofEpochSecond(epochSeconds)))).isEqualTo(expected);
    }

    @Test
    void acceptsTheAdjacentStepsOnly() {
        Instant now = Instant.ofEpochSecond(1_000_000_000L);
        long step = Totp.step(now);
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 1), now, null)).isEqualTo(step - 1);
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step + 1), now, null)).isEqualTo(step + 1);
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 2), now, null)).isEqualTo(-1);
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step + 2), now, null)).isEqualTo(-1);
    }

    @Test
    void aCodeCannotBeUsedTwice() {
        Instant now = Instant.ofEpochSecond(1_000_000_000L);
        long step = Totp.step(now);
        String code = Totp.code(RFC_SECRET, step);
        assertThat(Totp.verify(RFC_SECRET, code, now, null)).isEqualTo(step);
        assertThat(Totp.verify(RFC_SECRET, code, now, step)).isEqualTo(-1);
        // and an older code can't be used after a newer one
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 1), now, step)).isEqualTo(-1);
    }

    @Test
    void rejectsMalformedCodes() {
        Instant now = Instant.now();
        assertThat(Totp.verify(RFC_SECRET, null, now, null)).isEqualTo(-1);
        assertThat(Totp.verify(RFC_SECRET, "12345", now, null)).isEqualTo(-1);
        assertThat(Totp.verify(RFC_SECRET, "abcdef", now, null)).isEqualTo(-1);
        assertThat(Totp.verify(RFC_SECRET, "1234567", now, null)).isEqualTo(-1);
    }

    @Test
    void base32RoundTrips() {
        byte[] bytes = "sprout grows".getBytes(StandardCharsets.UTF_8);
        assertThat(Totp.base32Decode(Totp.base32Encode(bytes))).startsWith(bytes);
        assertThat(Totp.newSecret()).hasSize(32).matches("[A-Z2-7]+");
    }

    @Test
    void otpauthUriHasWhatAuthenticatorAppsNeed() {
        assertThat(Totp.otpauthUri("Sprout", "asha@example.com", "ABC"))
                .isEqualTo("otpauth://totp/Sprout:asha%40example.com?secret=ABC&issuer=Sprout&algorithm=SHA1&digits=6&period=30");
    }
}
