package org.example.authcommon.jwt;

/**
 * Имена и значения custom-claims, используемых в JWT платформы.
 * Общие для auth-module (эмитент) и resource-серверов (валидаторы).
 */
public final class JwtClaimNames {

    /**
     * Тип токена (claim {@code typ}): значение {@link #TYPE_ACCESS} для access-токенов.
     */
    public static final String TOKEN_TYPE = "typ";
    /**
     * Единственное допустимое значение {@link #TOKEN_TYPE} на resource-серверах.
     */
    public static final String TYPE_ACCESS = "access";
    /**
     * Идентификатор пользователя в access-токене.
     */
    public static final String USER_ID = "uid";
    /**
     * Роли пользователя в access-токене (объединение прямых ролей и ролей из групп).
     */
    public static final String ROLES = "roles";

    private JwtClaimNames() {
    }
}
