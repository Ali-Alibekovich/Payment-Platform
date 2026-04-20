package org.example.authmodule.jwt;

import java.time.Instant;
import java.util.Set;

/**
 * Типизированные claims access-токена.
 *
 * @param jti       уникальный идентификатор токена (JWT ID)
 * @param email     email пользователя (subject access-токена)
 * @param userId    идентификатор пользователя
 * @param roles     имена ролей пользователя (прямые + из групп)
 * @param expiresAt время истечения токена
 */
public record AccessClaims(
        String jti,
        String email,
        String userId,
        Set<String> roles,
        Instant expiresAt
) implements TokenClaims {

    @Override
    public TokenKind kind() {
        return TokenKind.ACCESS;
    }
}
