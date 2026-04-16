CREATE TABLE users
(
    id                    UUID PRIMARY KEY                  DEFAULT uuidv7(),
    email                 VARCHAR(255)             NOT NULL UNIQUE,
    password_hash         VARCHAR(255)             NOT NULL,
    full_name             VARCHAR(255)             NOT NULL,
    status                VARCHAR(20)              NOT NULL DEFAULT 'ACTIVE',
    failed_login_attempts INTEGER                  NOT NULL DEFAULT 0,
    locked_until          TIMESTAMP WITH TIME ZONE,
    anonymized_at         TIMESTAMP WITH TIME ZONE,
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

comment on table users is 'Зарегистрированные пользователи';
comment on column users.id is 'Идентификатор';
comment on column users.email is 'Почта';
comment on column users.password_hash is 'Захешированный пароль';
comment on column users.full_name is 'Полное имя пользователя';
comment on column users.status is 'Статус аккаунта';
comment on column users.failed_login_attempts is 'Количество неудачных попыток';
comment on column users.locked_until is 'Время разблокировки аккаунта';
comment on column users.anonymized_at is 'GDPR поле';
comment on column users.created_at is 'Время создания записи';
comment on column users.updated_at is 'Время изменения записи';
