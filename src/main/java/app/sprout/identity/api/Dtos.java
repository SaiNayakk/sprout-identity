package app.sprout.identity.api;

import app.sprout.identity.domain.IdentityService;
import app.sprout.identity.store.IdentityStore.UserRow;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

/** Request and response bodies, shaped exactly like the identity contract's schemas. */
public final class Dtos {

    private Dtos() {}

    public record SignUpRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotNull @Size(max = 128) String password,
            @NotBlank @Size(max = 60) String displayName) {
        /** Pasted emails often carry stray spaces; trim before validating. Passwords are left exactly as typed. */
        public SignUpRequest {
            email = email == null ? null : email.trim();
            displayName = displayName == null ? null : displayName.trim();
        }
    }

    public record SignInRequest(@NotBlank @Size(max = 254) String email, @NotNull @Size(max = 128) String password) {
        public SignInRequest {
            email = email == null ? null : email.trim();
        }
    }

    public record TotpVerifyRequest(@NotBlank @Size(max = 100) String challengeId, @NotNull @Pattern(regexp = "^[0-9]{6}$") String code) {}

    public record RefreshRequest(@NotBlank @Size(max = 200) String refreshToken) {}

    public record TotpConfirmRequest(@NotNull @Pattern(regexp = "^[0-9]{6}$") String code) {}

    public record User(UUID id, String email, String displayName, boolean totpEnabled, Instant createdAt) {
        static User of(UserRow row) {
            return new User(row.id(), row.email(), row.displayName(), row.totpEnabled(), row.createdAt());
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SignInResponse(String status, IdentityService.TokenPair tokens, String challengeId, Instant challengeExpiresAt) {
        static SignInResponse of(IdentityService.SignInResult r) {
            return new SignInResponse(r.status(), r.tokens(), r.challengeId(), r.challengeExpiresAt());
        }
    }
}
