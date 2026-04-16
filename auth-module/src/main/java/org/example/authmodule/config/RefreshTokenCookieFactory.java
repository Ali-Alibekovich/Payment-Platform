package org.example.authmodule.config;

import org.example.authmodule.properties.AuthCookieProperties;
import org.example.authmodule.properties.JwtProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RefreshTokenCookieFactory {

    private final AuthCookieProperties cookieProps;
    private final JwtProperties jwtProperties;

    public RefreshTokenCookieFactory(AuthCookieProperties cookieProps, JwtProperties jwtProperties) {
        this.cookieProps = cookieProps;
        this.jwtProperties = jwtProperties;
    }

    public ResponseCookie create(String refreshTokenValue) {
        long maxAgeSeconds = Duration.ofMillis(jwtProperties.refreshExpirationMs()).getSeconds();
        return baseBuilder(refreshTokenValue, maxAgeSeconds).build();
    }

    /**
     * Удаление cookie при logout.
     */
    public ResponseCookie clear() {
        return baseBuilder("", 0).maxAge(0).build();
    }

    private ResponseCookie.ResponseCookieBuilder baseBuilder(String value, long maxAgeSeconds) {
        return ResponseCookie.from(cookieProps.refreshTokenName(), value)
                .path(cookieProps.path())
                .maxAge(maxAgeSeconds)
                .httpOnly(cookieProps.httpOnly())
                .secure(cookieProps.secure())
                .sameSite(cookieProps.sameSite());
    }
}
