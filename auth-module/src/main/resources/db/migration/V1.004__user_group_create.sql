CREATE TABLE user_group
(
    user_id  UUID NOT NULL,
    group_id UUID NOT NULL,
    PRIMARY KEY (user_id, group_id),
    CONSTRAINT fk_user_group_user
        FOREIGN KEY (user_id)
            REFERENCES users (user_id)
            ON DELETE CASCADE,
    CONSTRAINT fk_user_group_group
        FOREIGN KEY (group_id)
            REFERENCES groups (group_id)
            ON DELETE CASCADE
);