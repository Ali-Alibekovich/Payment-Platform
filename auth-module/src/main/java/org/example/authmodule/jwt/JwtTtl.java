package org.example.authmodule.jwt;

import java.time.Instant;

/**
 * Утилита для расчёта TTL (в секундах) по времени истечения токена.
 */
public final class JwtTtl {

    /**
     * Возвращает, сколько секунд осталось до истечения.
     *
     * @param expiresAt момент истечения токена
     * @return количество секунд до истечения, не меньше 0
     */
    public static long secondsUntil(Instant expiresAt) {
        long ttl = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(ttl, 0);
    }
}
