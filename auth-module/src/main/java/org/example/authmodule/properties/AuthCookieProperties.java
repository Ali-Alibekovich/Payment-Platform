package org.example.authmodule.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.cookies")
public record AuthCookieProperties(
        String refreshTokenName,
        String path,
        boolean secure,
        String sameSite,
        boolean httpOnly
) {
}
