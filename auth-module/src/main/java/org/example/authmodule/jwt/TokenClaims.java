package org.example.authmodule.jwt;

import java.time.Instant;

/**
 * Разобранные claims выпущенного токена. Запечатано: только ACCESS / REFRESH.
 */
public sealed interface TokenClaims permits AccessClaims, RefreshClaims {

    /**
     * @return JWT ID (jti)
     */
    String jti();

    /**
     * @return идентификатор пользователя
     */
    String userId();

    /**
     * @return момент истечения токена
     */
    Instant expiresAt();

    /** @return тип токена */
    TokenKind kind();
}
