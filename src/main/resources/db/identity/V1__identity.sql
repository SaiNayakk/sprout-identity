-- Identity owns these tables; no other service reads them.

create table users (
    id                   uuid primary key,
    email                varchar(254) not null,
    email_normalized     varchar(254) not null unique,
    display_name         varchar(60)  not null,
    password_hash        varchar(100) not null,
    totp_secret          text,          -- AES-GCM encrypted, set once two-factor is confirmed
    totp_pending_secret  text,          -- AES-GCM encrypted, set during enrollment
    totp_last_step       bigint,        -- last accepted TOTP time step, so a code can't be replayed
    failed_attempts      int          not null default 0,
    locked_until         timestamptz,
    created_at           timestamptz  not null
);

create table sessions (
    id             uuid primary key,
    user_id        uuid        not null references users (id),
    created_at     timestamptz not null,
    expires_at     timestamptz not null,
    revoked_at     timestamptz,
    revoke_reason  varchar(40)
);
create index sessions_user_idx on sessions (user_id);

-- Refresh tokens are stored only as SHA-256 hashes. Each is single use; a session keeps
-- its chain of tokens so reuse of a spent one can revoke the whole session.
create table refresh_tokens (
    token_hash  char(64) primary key,
    session_id  uuid        not null references sessions (id),
    created_at  timestamptz not null,
    expires_at  timestamptz not null,
    used_at     timestamptz
);
create index refresh_tokens_session_idx on refresh_tokens (session_id);

create table totp_challenges (
    id          varchar(64) primary key,
    user_id     uuid        not null references users (id),
    created_at  timestamptz not null,
    expires_at  timestamptz not null,
    used_at     timestamptz,
    attempts    int         not null default 0
);

-- Transactional outbox: events are written in the same transaction as the change that
-- caused them, and a relay publishes them later. Nothing is lost if the bus is down.
create table outbox (
    id            uuid primary key,
    event_type    varchar(100) not null,
    payload       text         not null,
    created_at    timestamptz  not null,
    published_at  timestamptz
);
create index outbox_unpublished_idx on outbox (created_at) where published_at is null;
