package org.example.authmodule.jwt;

import java.time.Instant;

/**
 * Разобранные claims выпущенного токена. Запечатано: только ACCESS / REFRESH.
 */
public sealed interface TokenClaims permits AccessClaims, RefreshClaims {

    String jti();

    String userId();

    Instant expiresAt();

    TokenKind kind();
}
