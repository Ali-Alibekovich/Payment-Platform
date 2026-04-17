package org.example.authmodule.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Хранилище отозванных JWT по jti (Redis). Общее для access и refresh.
 * Предназначено для ограничения доступа пользователям выполнившие logout
 */
@Service
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

    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key(jti)));
    }

    private static String key(String jti) {
        return KEY_PREFIX + jti;
    }
}
