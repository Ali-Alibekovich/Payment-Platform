package org.example.authmodule.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authmodule.entity.User;
import org.example.authmodule.support.JwtTestSupport;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TokenKindTest {

    private final User user = JwtTestSupport.activeUser();

    @Test
    void accessClaimValueIsAccess() {
        assertThat(TokenKind.ACCESS.claimValue()).isEqualTo("access");
    }

    @Test
    void refreshClaimValueIsRefresh() {
        assertThat(TokenKind.REFRESH.claimValue()).isEqualTo("refresh");
    }

    @Test
    void accessExpirationTakenFromAccessProperty() {
        long ms = TokenKind.ACCESS.expirationMs(JwtTestSupport.defaultProperties());
        assertThat(ms).isEqualTo(JwtTestSupport.ACCESS_EXP_MS);
    }

    @Test
    void refreshExpirationTakenFromRefreshProperty() {
        long ms = TokenKind.REFRESH.expirationMs(JwtTestSupport.defaultProperties());
        assertThat(ms).isEqualTo(JwtTestSupport.REFRESH_EXP_MS);
    }

    @Test
    void accessSubjectIsEmail() {
        assertThat(TokenKind.ACCESS.subject(user)).isEqualTo(user.getEmail());
    }

    @Test
    void refreshSubjectIsUserId() {
        assertThat(TokenKind.REFRESH.subject(user)).isEqualTo(user.getUserId().toString());
    }

    @Test
    void accessProjectionExtractsAccessClaims() {
        Claims claims = parse(buildToken("access", user.getEmail(), user.getUserId().toString()));

        TokenClaims projected = TokenKind.ACCESS.project(claims);

        assertThat(projected).isInstanceOf(AccessClaims.class);
        AccessClaims access = (AccessClaims) projected;
        assertThat(access.email()).isEqualTo(user.getEmail());
        assertThat(access.userId()).isEqualTo(user.getUserId().toString());
        assertThat(access.jti()).isNotBlank();
    }

    @Test
    void refreshProjectionExtractsRefreshClaims() {
        Claims claims = parse(buildToken("refresh", user.getUserId().toString(), null));

        TokenClaims projected = TokenKind.REFRESH.project(claims);

        assertThat(projected).isInstanceOf(RefreshClaims.class);
        RefreshClaims refresh = (RefreshClaims) projected;
        assertThat(refresh.userId()).isEqualTo(user.getUserId().toString());
        assertThat(refresh.jti()).isNotBlank();
    }

    private static String buildToken(String typ, String subject, String uid) {
        var keys = JwtTestSupport.defaultKeys();
        var builder = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(JwtTestSupport.ISSUER)
                .subject(subject)
                .claim(JwtClaimNames.TOKEN_TYPE, typ)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000));
        if (uid != null) {
            builder.claim(JwtClaimNames.USER_ID, uid);
        }
        return builder.signWith(keys.signingKey()).compact();
    }

    private static Claims parse(String token) {
        return JwtTestSupport.defaultParser().parseSignedClaims(token).getPayload();
    }
}
