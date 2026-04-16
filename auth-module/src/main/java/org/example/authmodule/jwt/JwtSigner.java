package org.example.authmodule.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.example.authmodule.entity.User;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Выпускает токен любого {@link TokenKind}. Вся специфика вида живёт в самом
 * enum — здесь только оркестрация.
 */
@Component
public class JwtSigner {

    private final JwtKeys keys;

    public JwtSigner(JwtKeys keys) {
        this.keys = keys;
    }

    public String sign(TokenKind kind, User user) {
        var props = keys.properties();
        Instant now = Instant.now();
        Instant expiresAt = now.plusMillis(kind.expirationMs(props));

        JwtBuilder builder = Jwts.builder()
                .issuer(props.issuer())
                .id(UUID.randomUUID().toString())
                .subject(kind.subject(user))
                .claim(JwtClaimNames.TOKEN_TYPE, kind.claimValue())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(keys.signingKey());

        kind.enrich(builder, user);

        return builder.compact();
    }

    public int expiresInSeconds(TokenKind kind) {
        return Math.toIntExact(kind.expirationMs(keys.properties()) / 1000);
    }
}
