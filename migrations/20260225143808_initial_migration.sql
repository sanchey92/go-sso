-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS users
(
    id             UUID PRIMARY KEY             DEFAULT gen_random_uuid(),
    email          VARCHAR(255) UNIQUE NOT NULL CHECK (email = lower(email)),
    password_hash  TEXT,
    email_verified BOOLEAN             NOT NULL DEFAULT false,
    mfa_enabled    BOOLEAN             NOT NULL DEFAULT false,
    mfa_secret_enc BYTEA,
    status         VARCHAR(20)         NOT NULL DEFAULT 'active',
    created_at     TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ         NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_clients
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    secret_hash     TEXT        NOT NULL,
    name            VARCHAR(255),
    redirect_uris   TEXT[],
    allowed_scopes  TEXT[],
    is_confidential BOOLEAN,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    token_hash TEXT UNIQUE NOT NULL,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  UUID        NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    family_id  UUID        NOT NULL,
    scopes     TEXT[],
    revoked    BOOLEAN     NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
