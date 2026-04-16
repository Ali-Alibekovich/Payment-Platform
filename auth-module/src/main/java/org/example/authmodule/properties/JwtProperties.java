package org.example.authmodule.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String secret,
        String issuer,
        long clockSkewSeconds,
        long accessExpirationMs,
        long refreshExpirationMs
) {
}
