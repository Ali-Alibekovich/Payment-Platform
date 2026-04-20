package org.example.authmodule.jwt;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTtlTest {

    @Test
    void returnsPositiveSecondsForFutureExpiry() {
        Instant in1Hour = Instant.now().plus(Duration.ofHours(1));

        long ttl = JwtTtl.secondsUntil(in1Hour);

        assertThat(ttl).isBetween(3590L, 3600L);
    }

    @Test
    void returnsZeroForPastExpiry() {
        Instant past = Instant.now().minus(Duration.ofMinutes(10));

        assertThat(JwtTtl.secondsUntil(past)).isZero();
    }

    @Test
    void returnsZeroForNow() {
        assertThat(JwtTtl.secondsUntil(Instant.now())).isBetween(0L, 1L);
    }
}
