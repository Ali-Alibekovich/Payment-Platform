package org.example.authmodule.service;

import org.example.authcommon.security.JtiBlacklistStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JtiBlacklistStoreTest {

    @SuppressWarnings("unchecked")
    private final RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);

    @SuppressWarnings("unchecked")
    private final ValueOperations<String, Object> valueOps = mock(ValueOperations.class);

    private JtiBlacklistStore store;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        store = new JtiBlacklistStore(redisTemplate);
    }

    @Test
    void revokeStoresKeyWithPrefixAndTtl() {
        store.revokeUntilExpiry("abc-jti", 60);

        verify(valueOps).set(eq("auth:blacklist:jti:abc-jti"), eq("1"), eq(60L), eq(TimeUnit.SECONDS));
    }

    @Test
    void revokeIgnoresNullJti() {
        store.revokeUntilExpiry(null, 60);

        verify(valueOps, never()).set(any(), any(), anyLong(), any());
    }

    @Test
    void revokeIgnoresBlankJti() {
        store.revokeUntilExpiry("   ", 60);

        verify(valueOps, never()).set(any(), any(), anyLong(), any());
    }

    @Test
    void isRevokedTrueWhenKeyExists() {
        when(redisTemplate.hasKey("auth:blacklist:jti:abc")).thenReturn(true);

        assertThat(store.isRevoked("abc")).isTrue();
    }

    @Test
    void isRevokedFalseWhenKeyAbsent() {
        when(redisTemplate.hasKey("auth:blacklist:jti:abc")).thenReturn(false);

        assertThat(store.isRevoked("abc")).isFalse();
    }

    @Test
    void isRevokedFalseWhenHasKeyReturnsNull() {
        when(redisTemplate.hasKey("auth:blacklist:jti:abc")).thenReturn(null);

        assertThat(store.isRevoked("abc")).isFalse();
    }
}
