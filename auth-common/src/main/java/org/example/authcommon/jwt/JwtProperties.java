package org.example.authcommon.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Общие настройки JWT. Поля {@link #accessExpirationMs()} и
 * {@link #refreshExpirationMs()} используются только эмитентом (auth-module);
 * resource-серверам достаточно {@code secret}, {@code issuer},
 * {@code clockSkewSeconds}.
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        String issuer,
        long clockSkewSeconds,
        long accessExpirationMs,
        long refreshExpirationMs
) {
}
