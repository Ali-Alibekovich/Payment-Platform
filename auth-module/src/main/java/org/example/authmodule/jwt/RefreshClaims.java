package org.example.authmodule.jwt;

import java.time.Instant;

/**
 * Типизированные claims refresh-токена.
 *
 * @param jti       уникальный идентификатор токена (JWT ID)
 * @param userId    идентификатор пользователя (subject refresh-токена)
 * @param expiresAt время истечения токена
 */
public record RefreshClaims(
        String jti,
        String userId,
        Instant expiresAt
) implements TokenClaims {

    @Override
    public TokenKind kind() {
        return TokenKind.REFRESH;
    }
}
