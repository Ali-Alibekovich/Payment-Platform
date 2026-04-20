package org.example.authmodule.config;

import org.example.authcommon.jwt.JwtProperties;
import org.example.authmodule.properties.AuthCookieProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Фабрика для создания cookie с refresh token
 */
@Component
public class RefreshTokenCookieFactory {

    private final AuthCookieProperties cookieProps;
    private final JwtProperties jwtProperties;

    public RefreshTokenCookieFactory(AuthCookieProperties cookieProps, JwtProperties jwtProperties) {
        this.cookieProps = cookieProps;
        this.jwtProperties = jwtProperties;
    }

    /**
     * Создание ResponseCookie
     *
     * @param refreshTokenValue refresh токен
     * @return ResponseCookie куки с заполненным refresh токен
     */
    public ResponseCookie create(String refreshTokenValue) {
        long maxAgeSeconds = Duration.ofMillis(jwtProperties.refreshExpirationMs()).getSeconds();
        return baseBuilder(refreshTokenValue, maxAgeSeconds).build();
    }

    /**
     * Удаление cookie при logout.
     * @return ResponseCookie очищенные куки
     */
    public ResponseCookie clear() {
        return baseBuilder("", 0).maxAge(0).build();
    }

    /**
     * Сборка cookies
     *
     * @param value         значение для cookie (например eyJhbGciOi...)
     * @param maxAgeSeconds время жизни cookie
     * @return Builder cookie для сбора ответа
     */
    private ResponseCookie.ResponseCookieBuilder baseBuilder(String value, long maxAgeSeconds) {
        return ResponseCookie.from(cookieProps.refreshTokenName(), value)
                .path(cookieProps.path())
                .maxAge(maxAgeSeconds)
                .httpOnly(cookieProps.httpOnly())
                .secure(cookieProps.secure())
                .sameSite(cookieProps.sameSite());
    }
}
