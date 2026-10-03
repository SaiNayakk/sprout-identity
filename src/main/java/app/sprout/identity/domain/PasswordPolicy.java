package app.sprout.identity.domain;

import java.util.Locale;
import java.util.Set;

/**
 * Length beats complexity rules (NIST SP 800-63B): at least 10 characters, at most 128, not a
 * well-known password, and not the email's own name part.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 10;
    public static final int MAX_LENGTH = 128;

    private static final Set<String> COMMON = Set.of(
            "1234567890", "12345678910", "0123456789", "1234554321", "1111111111", "0000000000",
            "password12", "password123", "password1234", "passw0rd123", "qwertyuiop", "qwerty1234",
            "qwerty12345", "1q2w3e4r5t", "1qaz2wsx3edc", "asdfghjkl1", "iloveyou12", "iloveyou123",
            "abcdefghij", "abcd123456", "abc1234567", "welcome123", "letmein123", "football12",
            "monkey1234", "dragon1234", "sunshine12", "princess12", "baseball12", "superman12",
            "trustno123", "123456789a", "a123456789", "zxcvbnm123", "india12345", "india@1234",
            "sachin1234", "krishna123", "ganesh1234", "mumbai1234", "cricket123", "password@123",
            "admin12345", "changeme12", "secret1234", "loveyou123", "123123123123", "987654321a");

    private PasswordPolicy() {}

    /** Throws {@link ErrorCode#WEAK_PASSWORD} with a plain reason when the password breaks a rule. */
    public static void check(String password, String email) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new IdentityException(ErrorCode.WEAK_PASSWORD, "Use at least " + MIN_LENGTH + " characters.");
        }
        if (password.length() > MAX_LENGTH) {
            throw new IdentityException(ErrorCode.WEAK_PASSWORD, "Use at most " + MAX_LENGTH + " characters.");
        }
        String lower = password.toLowerCase(Locale.ROOT);
        if (COMMON.contains(lower) || lower.chars().distinct().count() < 4) {
            throw new IdentityException(ErrorCode.WEAK_PASSWORD, "That password is too easy to guess. Try a few unrelated words.");
        }
        if (email != null) {
            String name = email.toLowerCase(Locale.ROOT).split("@")[0];
            if (name.length() >= 4 && lower.contains(name)) {
                throw new IdentityException(ErrorCode.WEAK_PASSWORD, "Don't use your email in your password.");
            }
        }
    }
}
