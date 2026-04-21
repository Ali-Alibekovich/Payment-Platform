CREATE TABLE refresh_tokens
(
    id              UUID PRIMARY KEY      DEFAULT uuidv7(),
    user_id         UUID         NOT NULL REFERENCES users (user_id),
    token_family_id UUID         NOT NULL,
    token_hash      VARCHAR(255) NOT NULL UNIQUE,
    status          VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE', --
    expires_at      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_user_family ON refresh_tokens (user_id, token_family_id);
CREATE INDEX idx_refresh_active ON refresh_tokens (user_id) WHERE status = 'ACTIVE';
