package app.sprout.identity.domain;

import org.springframework.http.HttpStatus;

/** The stable error codes from the identity contract, each with its HTTP status and title. */
public enum ErrorCode {
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "The request isn't valid"),
    WEAK_PASSWORD(HttpStatus.BAD_REQUEST, "Choose a stronger password"),
    EMAIL_TAKEN(HttpStatus.CONFLICT, "An account with this email already exists"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Wrong email or password"),
    ACCOUNT_LOCKED(HttpStatus.LOCKED, "Too many failed attempts"),
    INVALID_TOTP(HttpStatus.UNAUTHORIZED, "That code didn't work"),
    CHALLENGE_EXPIRED(HttpStatus.UNAUTHORIZED, "This sign-in attempt expired"),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Sign in again"),
    REFRESH_TOKEN_REUSED(HttpStatus.UNAUTHORIZED, "This session was ended for your safety"),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "Sign in to continue"),
    TOTP_ALREADY_ENABLED(HttpStatus.CONFLICT, "Two-factor is already on"),
    TOTP_NOT_STARTED(HttpStatus.CONFLICT, "Start two-factor setup first");

    private final HttpStatus status;
    private final String title;

    ErrorCode(HttpStatus status, String title) {
        this.status = status;
        this.title = title;
    }

    public HttpStatus status() {
        return status;
    }

    public String title() {
        return title;
    }
}
