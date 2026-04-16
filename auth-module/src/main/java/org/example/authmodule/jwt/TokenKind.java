package org.example.authmodule.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import org.example.authmodule.entity.User;
import org.example.authmodule.properties.JwtProperties;

/**
 * Стратегия для каждого вида токена: TTL, subject, дополнительные claims и
 * обратная проекция parsed Claims → {@link TokenClaims}. Новый вид токена
 * добавляется одной константой, не меняя остальной код.
 */
public enum TokenKind {

    ACCESS("access") {
        @Override
        public long expirationMs(JwtProperties properties) {
            return properties.accessExpirationMs();
        }

        @Override
        public String subject(User user) {
            return user.getEmail();
        }

        @Override
        public void enrich(JwtBuilder builder, User user) {
            builder.claim(JwtClaimNames.USER_ID, user.getId().toString());
        }

        @Override
        public TokenClaims project(Claims claims) {
            return new AccessClaims(
                    claims.getId(),
                    claims.getSubject(),
                    claims.get(JwtClaimNames.USER_ID, String.class),
                    claims.getExpiration().toInstant()
            );
        }
    },

    REFRESH("refresh") {
        @Override
        public long expirationMs(JwtProperties properties) {
            return properties.refreshExpirationMs();
        }

        @Override
        public String subject(User user) {
            return user.getId().toString();
        }

        @Override
        public void enrich(JwtBuilder builder, User user) {
            // no extra claims
        }

        @Override
        public TokenClaims project(Claims claims) {
            return new RefreshClaims(
                    claims.getId(),
                    claims.getSubject(),
                    claims.getExpiration().toInstant()
            );
        }
    };

    private final String claimValue;

    TokenKind(String claimValue) {
        this.claimValue = claimValue;
    }

    public String claimValue() {
        return claimValue;
    }

    public abstract long expirationMs(JwtProperties properties);

    public abstract String subject(User user);

    public abstract void enrich(JwtBuilder builder, User user);

    public abstract TokenClaims project(Claims claims);
}
