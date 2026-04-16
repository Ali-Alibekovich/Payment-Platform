package org.example.authmodule.jwt;

import java.time.Instant;

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
