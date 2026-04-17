package org.example.authmodule.jwt;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.example.authmodule.properties.JwtProperties;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Инфраструктура JWT: секретный ключ и предсобранный парсер. Изолирует
 * остальной код от деталей jjwt и конфигурации.
 */
@Component
public class JwtKeys {

    private final JwtProperties properties;
    private final SecretKey signingKey;
    private final JwtParser parser;

    public JwtKeys(JwtProperties properties) {
        if (properties.secret() == null || properties.secret().isBlank()) {
            throw new IllegalStateException(
                    "jwt.secret must be set (e.g. JWT_SECRET env in production)");
        }
        this.properties = properties;
        this.signingKey = deriveKey(properties.secret());
        this.parser = Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(properties.issuer())
                .clockSkewSeconds(properties.clockSkewSeconds())
                .build();
    }

    /**
     * @return настройки JWT из конфигурации приложения
     */
    public JwtProperties properties() {
        return properties;
    }

    /**
     * @return симметричный ключ подписи
     */
    public SecretKey signingKey() {
        return signingKey;
    }

    /**
     * @return преднастроенный парсер JWT с проверкой issuer и clock skew
     */
    public JwtParser parser() {
        return parser;
    }

    private static SecretKey deriveKey(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
