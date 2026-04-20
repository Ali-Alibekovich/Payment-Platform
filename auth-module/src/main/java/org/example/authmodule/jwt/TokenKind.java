package org.example.authmodule.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.jwt.JwtProperties;
import org.example.authmodule.entity.Role;
import org.example.authmodule.entity.User;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
            builder.claim(JwtClaimNames.USER_ID, user.getUserId().toString());
            builder.claim(JwtClaimNames.ROLES, collectRoleNames(user));
        }

        @Override
        public TokenClaims project(Claims claims) {
            Object raw = claims.get(JwtClaimNames.ROLES);
            Set<String> roles = raw instanceof Collection<?> c
                    ? c.stream().map(Object::toString).collect(Collectors.toUnmodifiableSet())
                    : Set.of();
            return new AccessClaims(
                    claims.getId(),
                    claims.getSubject(),
                    claims.get(JwtClaimNames.USER_ID, String.class),
                    roles,
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
            return user.getUserId().toString();
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

    private static List<String> collectRoleNames(User user) {
        Stream<Role> direct = user.getRoles() == null ? Stream.empty() : user.getRoles().stream();
        Stream<Role> fromGroups = user.getGroups() == null
                ? Stream.empty()
                : user.getGroups().stream()
                .filter(Objects::nonNull)
                .flatMap(g -> g.getRoles() == null ? Stream.empty() : g.getRoles().stream());
        return Stream.concat(direct, fromGroups)
                .filter(Objects::nonNull)
                .map(Role::getRoleName)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(TreeSet::new))
                .stream()
                .toList();
    }
}
