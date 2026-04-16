package org.example.authmodule.jwt;

import java.time.Instant;

public final class JwtTtl {

    private JwtTtl() {
    }

    public static long secondsUntil(Instant expiresAt) {
        long ttl = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(ttl, 0);
    }
}
