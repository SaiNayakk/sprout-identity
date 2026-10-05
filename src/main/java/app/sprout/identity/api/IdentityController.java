package app.sprout.identity.api;

import app.sprout.identity.api.Dtos.RefreshRequest;
import app.sprout.identity.api.Dtos.SignInRequest;
import app.sprout.identity.api.Dtos.SignInResponse;
import app.sprout.identity.api.Dtos.SignUpRequest;
import app.sprout.identity.api.Dtos.TotpConfirmRequest;
import app.sprout.identity.api.Dtos.TotpVerifyRequest;
import app.sprout.identity.api.Dtos.User;
import app.sprout.identity.domain.ErrorCode;
import app.sprout.identity.domain.IdentityException;
import app.sprout.identity.domain.IdentityService;
import app.sprout.identity.domain.TokenService;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** HTTP endpoints of the identity contract (sprout-contracts: identity-v1.yaml). */
@RestController
public class IdentityController {

    public record DemoUserRequest(String email, String password, String displayName) {}

    private final IdentityService identity;
    private final TokenService tokens;
    private final app.sprout.identity.config.IdentityProperties props;

    public IdentityController(IdentityService identity, TokenService tokens, app.sprout.identity.config.IdentityProperties props) {
        this.props = props;
        this.identity = identity;
        this.tokens = tokens;
    }

    @PostMapping(path = "/v1/users", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public User signUp(@Valid @RequestBody SignUpRequest req) {
        return User.of(identity.signUp(req.email(), req.password(), req.displayName()));
    }

    /** For the sandbox service: a fictional customer. Not there at all unless the sandbox is switched on here. */
    @PostMapping(path = "/internal/v1/demo-users", consumes = MediaType.APPLICATION_JSON_VALUE)
    public User demoUser(@RequestHeader(name = "X-Service-Key", required = false) String key, @RequestBody DemoUserRequest req)
            throws org.springframework.web.servlet.resource.NoResourceFoundException {
        if (props.demo() == null || !props.demo().enabled()) {
            throw new org.springframework.web.servlet.resource.NoResourceFoundException(org.springframework.http.HttpMethod.POST,
                    "internal/v1/demo-users");
        }
        if (key == null || !java.security.MessageDigest.isEqual(key.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                props.demo().serviceKey().getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            throw new IdentityException(ErrorCode.UNAUTHENTICATED, "Only Sprout services can call this.");
        }
        return User.of(identity.demoUser(req.email(), req.password(), req.displayName()));
    }

    @GetMapping("/v1/users/me")
    public User me(@RequestHeader(name = "Authorization", required = false) String auth) {
        return User.of(identity.user(identity.authenticate(bearer(auth)).userId()));
    }

    @PostMapping(path = "/v1/sessions", consumes = MediaType.APPLICATION_JSON_VALUE)
    public SignInResponse signIn(@Valid @RequestBody SignInRequest req) {
        return SignInResponse.of(identity.signIn(req.email(), req.password()));
    }

    @PostMapping(path = "/v1/sessions/totp", consumes = MediaType.APPLICATION_JSON_VALUE)
    public SignInResponse completeTotp(@Valid @RequestBody TotpVerifyRequest req) {
        return SignInResponse.of(identity.completeTotp(req.challengeId(), req.code()));
    }

    @DeleteMapping("/v1/sessions/current")
    public ResponseEntity<Void> signOut(@RequestHeader(name = "Authorization", required = false) String auth) {
        identity.signOut(identity.authenticate(bearer(auth)));
        return ResponseEntity.noContent().build();
    }

    @PostMapping(path = "/v1/tokens/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
    public IdentityService.TokenPair refresh(@Valid @RequestBody RefreshRequest req) {
        return identity.refresh(req.refreshToken());
    }

    @PostMapping("/v1/users/me/totp")
    public IdentityService.Enrollment startTotp(@RequestHeader(name = "Authorization", required = false) String auth) {
        return identity.startTotp(identity.authenticate(bearer(auth)).userId());
    }

    @PostMapping(path = "/v1/users/me/totp/confirm", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> confirmTotp(@RequestHeader(name = "Authorization", required = false) String auth,
                                            @Valid @RequestBody TotpConfirmRequest req) {
        identity.confirmTotp(identity.authenticate(bearer(auth)).userId(), req.code());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return tokens.jwks();
    }

    private static String bearer(String header) {
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7) || header.length() < 8) {
            throw new IdentityException(ErrorCode.UNAUTHENTICATED, "Sign in to continue.");
        }
        return header.substring(7).trim();
    }
}
