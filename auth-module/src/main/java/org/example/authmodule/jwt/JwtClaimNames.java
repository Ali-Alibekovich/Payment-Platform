package org.example.authmodule.jwt;

/**
 * Имена custom-claims, используемых в токенах.
 */
public final class JwtClaimNames {

    /**
     * Тип токена: {@code access} или {@code refresh}.
     */
    public static final String TOKEN_TYPE = "typ";
    /**
     * Идентификатор пользователя в access-токене.
     */
    public static final String USER_ID = "uid";

    private JwtClaimNames() {
    }
}
