package org.example.authcommon.security;

import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Хранилище отозванных JWT по jti (Redis). Общее для access и refresh.
 * Используется эмитентом (для отзыва на logout/rotate) и resource-серверами
 * (для проверки валидности через {@link JtiBlacklistValidator}).
 */
public class JtiBlacklistStore {

    private static final String KEY_PREFIX = "auth:blacklist:jti:";

    private final RedisTemplate<String, Object> redisTemplate;

    public JtiBlacklistStore(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void revokeUntilExpiry(String jti, long ttlSeconds) {
        if (jti == null || jti.isBlank()) {
            return;
        }
        redisTemplate.opsForValue().set(key(jti), "1", ttlSeconds, TimeUnit.SECONDS);
    }

    /**
     * Атомарная проверка-и-отзыв (Redis SET NX EX). Возвращает {@code true}
     * если именно этот вызов пометил jti отозванным; {@code false} — если
     * отзыв уже существовал (признак reuse-атаки или повторного logout).
     */
    public boolean tryRevoke(String jti, long ttlSeconds) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        long effectiveTtl = Math.max(1L, ttlSeconds);
        Boolean set = redisTemplate.opsForValue()
                .setIfAbsent(key(jti), "1", Duration.ofSeconds(effectiveTtl));
        return Boolean.TRUE.equals(set);
    }

    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key(jti)));
    }

    private static String key(String jti) {
        return KEY_PREFIX + jti;
    }
}
