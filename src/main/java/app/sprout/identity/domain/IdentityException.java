package app.sprout.identity.domain;

/** A failure the client should see, carrying one of the contract's error codes. */
public class IdentityException extends RuntimeException {

    private final ErrorCode code;
    private final Long retryAfterSeconds;

    public IdentityException(ErrorCode code, String detail) {
        this(code, detail, null);
    }

    public IdentityException(ErrorCode code, String detail, Long retryAfterSeconds) {
        super(detail);
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public ErrorCode code() {
        return code;
    }

    public Long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
