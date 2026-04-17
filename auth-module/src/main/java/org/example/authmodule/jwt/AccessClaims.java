package org.example.authmodule.jwt;

import java.time.Instant;

/**
 * Типизированные claims access-токена.
 *
 * @param jti       уникальный идентификатор токена (JWT ID)
 * @param email     email пользователя (subject access-токена)
 * @param userId    идентификатор пользователя
 * @param expiresAt время истечения токена
 */
public record AccessClaims(
        String jti,
        String email,
        String userId,
        Instant expiresAt
) implements TokenClaims {

    @Override
    public TokenKind kind() {
        return TokenKind.ACCESS;
    }
}
