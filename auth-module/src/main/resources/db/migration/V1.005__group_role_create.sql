CREATE TABLE group_role
(
    group_id UUID NOT NULL,
    role_id  UUID NOT NULL,
    PRIMARY KEY (group_id, role_id),
    CONSTRAINT fk_group_role_group
        FOREIGN KEY (group_id)
            REFERENCES groups (group_id)
            ON DELETE CASCADE,
    CONSTRAINT fk_group_role_role
        FOREIGN KEY (role_id)
            REFERENCES roles (role_id)
            ON DELETE CASCADE
);