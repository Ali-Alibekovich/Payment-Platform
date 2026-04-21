CREATE TABLE groups
(
    group_id   UUID PRIMARY KEY DEFAULT uuidv7(),
    group_name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

