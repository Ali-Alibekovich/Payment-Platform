CREATE TABLE roles
(
    role_id   UUID PRIMARY KEY DEFAULT uuidv7(),
    role_name  VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);