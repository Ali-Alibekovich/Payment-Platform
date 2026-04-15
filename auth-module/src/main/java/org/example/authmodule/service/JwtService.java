package org.example.authmodule.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.example.authmodule.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Component
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private static final String CLAIM_TOKEN_TYPE = "typ";
    private static final String CLAIM_USER_ID = "uid";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private final SecretKey signingKey;
    private final String issuer;
    private final long accessExpirationMs;
    private final long refreshExpirationMs;
    private final JwtParser jwtParser;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.issuer}") String issuer,
            @Value("${jwt.access-expiration-ms}") long accessExpirationMs,
            @Value("${jwt.refresh-expiration-ms}") long refreshExpirationMs,
            @Value("${jwt.clock-skew-seconds:60}") long clockSkewSeconds
    ) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("jwt.secret must be set (e.g. JWT_SECRET env in production)");
        }
        this.signingKey = signingKeyFromSecret(secret);
        this.issuer = issuer;
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
        this.jwtParser = Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(this.issuer)
                .clockSkewSeconds(clockSkewSeconds)
                .build();
    }

    /**
     * Детерминированно получаем 256-битный ключ HMAC-SHA256 из строки секрета (как в проде с длинным env-секретом).
     */
    private static SecretKey signingKeyFromSecret(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(issuer)
                .subject(user.getEmail())
                .claim(CLAIM_USER_ID, user.getId().toString())
                .claim(CLAIM_TOKEN_TYPE, TYPE_ACCESS)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(accessExpirationMs)))
                .signWith(signingKey)
                .compact();
    }

    public String generateRefreshToken(User user) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(issuer)
                .subject(user.getId().toString())
                .claim(CLAIM_TOKEN_TYPE, TYPE_REFRESH)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(refreshExpirationMs)))
                .signWith(signingKey)
                .compact();
    }

    public int getAccessTokenExpirationSeconds() {
        return Math.toIntExact(accessExpirationMs / 1000);
    }

    /**
     * Проверка access-токена (подпись, срок, issuer, тип {@code access}).
     */
    public boolean validateToken(String token) {
        return parseAccessTokenClaims(token).isPresent();
    }

    public boolean isRefreshTokenValid(String token) {
        return parseRefreshTokenClaims(token).isPresent();
    }

    public Optional<String> getEmailFromAccessToken(String token) {
        return parseAccessTokenClaims(token).map(Claims::getSubject);
    }

    /**
     * Subject access-токена — email пользователя.
     */
    public Optional<UUID> getUserIdFromAccessToken(String token) {
        return parseAccessTokenClaims(token)
                .map(c -> c.get(CLAIM_USER_ID, String.class))
                .map(UUID::fromString);
    }

    public Optional<UUID> getUserIdFromRefreshToken(String token) {
        return parseRefreshTokenClaims(token).map(c -> UUID.fromString(c.getSubject()));
    }

    private Optional<Claims> parseAccessTokenClaims(String token) {
        return parseClaims(token, TYPE_ACCESS);
    }

    private Optional<Claims> parseRefreshTokenClaims(String token) {
        return parseClaims(token, TYPE_REFRESH);
    }

    private Optional<Claims> parseClaims(String token, String expectedType) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            Claims claims = jwtParser.parseSignedClaims(token).getPayload();
            String typ = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (!expectedType.equals(typ)) {
                log.debug("JWT typ mismatch: expected {}, token had {}", expectedType, typ);
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
