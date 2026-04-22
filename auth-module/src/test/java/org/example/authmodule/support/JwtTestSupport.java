package org.example.authmodule.support;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.example.authcommon.jwt.JwtKeys;
import org.example.authcommon.jwt.JwtProperties;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.entity.User;

import java.time.Instant;
import java.util.UUID;

import static org.example.authmodule.service.SessionTokensService.hashToken;

/**
 * Общие фикстуры для JWT-тестов: дефолтные properties/keys и прогруз пользователя.
 */
public final class JwtTestSupport {

    public static final String SECRET = "super-secret-test-key-must-be-long-enough-123";
    public static final String ISSUER = "auth-module-test";
    public static final long CLOCK_SKEW_SECONDS = 5;
    public static final long ACCESS_EXP_MS = 5 * 60 * 1000L;
    public static final long REFRESH_EXP_MS = 24 * 60 * 60 * 1000L;

    private JwtTestSupport() {
    }

    public static JwtProperties defaultProperties() {
        return new JwtProperties(SECRET, ISSUER, CLOCK_SKEW_SECONDS, ACCESS_EXP_MS, REFRESH_EXP_MS);
    }

    public static JwtKeys defaultKeys() {
        return new JwtKeys(defaultProperties());
    }

    public static JwtParser defaultParser() {
        JwtKeys keys = defaultKeys();
        return Jwts.parser()
                .verifyWith(keys.signingKey())
                .requireIssuer(ISSUER)
                .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                .build();
    }

    public static User activeUser() {
        User user = new User();
        user.setUserId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setFullName("Test User");
        user.setPasswordHash(hashToken("rt"));
        user.setStatus(UserStatus.ACTIVE);
        user.setFailedLoginAttempts(0);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        return user;
    }
}
