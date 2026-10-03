# sprout-identity

Accounts, passwords, two-factor and tokens for **Sprout**, a simulated end-to-end brokerage. It implements the [identity contract](https://github.com/SaiNayakk/sprout-contracts/blob/main/src/main/resources/sprout/contracts/openapi/identity-v1.yaml); architecture, environments and test evidence live in [sprout-platform](https://github.com/SaiNayakk/sprout-platform).

## What it does

| Endpoint | Purpose |
|---|---|
| `POST /v1/users` | Sign up |
| `POST /v1/sessions` | Sign in with email and password |
| `POST /v1/sessions/totp` | Finish sign-in with a two-factor code |
| `POST /v1/tokens/refresh` | Rotate tokens |
| `DELETE /v1/sessions/current` | Sign out |
| `GET /v1/users/me` | The signed-in account |
| `POST /v1/users/me/totp`, `/confirm` | Turn on two-factor |
| `GET /.well-known/jwks.json` | Public keys for verifying access tokens |

## Security design

- **Passwords:** bcrypt. At least 10 characters, not a common password and not the email's name part (NIST 800-63B style: length over complexity rules).
- **Lockout:** five wrong passwords or two-factor codes lock the account for 15 minutes, with `Retry-After`. Unknown emails take as long as wrong passwords, so timing doesn't reveal which accounts exist.
- **Two-factor:** TOTP (RFC 6238) written from scratch and tested against the RFC's own vectors. Secrets are encrypted at rest with AES-256-GCM; each code works once; ±30 s clock tolerance.
- **Access tokens:** RS256 JWTs, 15 minutes, verified by the gateway with the published JWKS. Identity re-checks that the session wasn't ended.
- **Refresh tokens:** opaque, stored only as SHA-256 hashes, single use and rotated on every refresh. A spent token presented again is treated as theft and **revokes the whole session**. Marking a token used is one atomic update, so two racing requests can't both win.
- **Events:** sign-up writes `identity.user.registered` to a transactional **outbox** in the same transaction, so the event can't be lost or sent for a rollback.
- **Errors:** RFC 9457 problem details with stable codes and the request id.

## Run it

Needs Java 21 and Postgres.

```bash
export IDENTITY_TOTP_KEY=$(openssl rand -base64 32)
mvn spring-boot:run
```

| Variable | Default | Meaning |
|---|---|---|
| `IDENTITY_DB_URL` | `jdbc:postgresql://localhost:5432/sprout?currentSchema=identity` | Database (the service owns the `identity` schema) |
| `IDENTITY_TOTP_KEY` | none, required | Base64 of 32 random bytes; encrypts TOTP secrets |
| `IDENTITY_SIGNING_KEY_PATH` | empty: a new key per start | PEM RSA key that signs access tokens |
| `IDENTITY_PORT` / `IDENTITY_BIND` | `8101` / `127.0.0.1` | Listen address; only the gateway should reach it |
| `OTEL_ENABLED` | `false` | Export metrics and traces over OTLP |

In production the service runs inside the **edge host** JVM alongside the gateway (see sprout-platform); its settings live in `identity.yml` so co-hosted services never read each other's config.

## Tests

`mvn verify` runs:

- **Unit tests:** TOTP against RFC 6238 vectors, the password policy, encryption and tamper detection.
- **API tests:** against a real Postgres (Testcontainers). **Every response is validated against the published contract** from `sprout-contracts`. Covers lockout and unlock, two-factor replay, challenge expiry, refresh rotation and theft detection, a concurrent refresh race, sign-out, and tampered and expired tokens.

## License

MIT
