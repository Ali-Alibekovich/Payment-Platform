package org.example.authmodule.jwt;

import java.time.Instant;

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
