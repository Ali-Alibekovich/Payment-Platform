package org.example.authmodule.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.jwt.JwtKeys;
import org.example.authmodule.entity.User;
import org.springframework.stereotype.Component;

import java.time.Clock;
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
    private final Clock clock;

    public JwtSigner(JwtKeys keys, Clock clock) {
        this.keys = keys;
        this.clock = clock;
    }

    /**
     * Подписывает JWT заданного вида для пользователя.
     *
     * @param kind тип токена (access/refresh)
     * @param user пользователь
     * @return сериализованный JWT
     */
    public String sign(TokenKind kind, User user) {
        var props = keys.properties();
        Instant now = clock.instant();
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

    /**
     * Возвращает TTL токена в секундах для HTTP-ответов/клиентов.
     *
     * @param kind тип токена
     * @return время жизни в секундах
     */
    public int expiresInSeconds(TokenKind kind) {
        return Math.toIntExact(kind.expirationMs(keys.properties()) / 1000);
    }
}
