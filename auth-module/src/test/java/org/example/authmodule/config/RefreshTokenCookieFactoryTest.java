package org.example.authmodule.config;

import org.example.authcommon.jwt.JwtProperties;
import org.example.authmodule.properties.AuthCookieProperties;
import org.example.authmodule.support.JwtTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokenCookieFactoryTest {

    private RefreshTokenCookieFactory factory;
    private JwtProperties jwtProps;

    @BeforeEach
    void setUp() {
        AuthCookieProperties cookieProps = new AuthCookieProperties("refresh_token", "/api/v1/auth", true, "Strict", true);
        jwtProps = JwtTestSupport.defaultProperties();
        factory = new RefreshTokenCookieFactory(cookieProps, jwtProps);
    }

    @Test
    void createSetsValueAndAttributes() {
        ResponseCookie cookie = factory.create("token-value");

        assertThat(cookie.getName()).isEqualTo("refresh_token");
        assertThat(cookie.getValue()).isEqualTo("token-value");
        assertThat(cookie.getPath()).isEqualTo("/api/v1/auth");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        long expectedSeconds = Duration.ofMillis(jwtProps.refreshExpirationMs()).getSeconds();
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofSeconds(expectedSeconds));
    }

    @Test
    void clearReturnsEmptyValueWithZeroMaxAge() {
        ResponseCookie cookie = factory.clear();

        assertThat(cookie.getName()).isEqualTo("refresh_token");
        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ZERO);
        assertThat(cookie.isHttpOnly()).isTrue();
    }
}
