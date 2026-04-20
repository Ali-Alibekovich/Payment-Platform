package org.example.authmodule.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.jwt.JwtKeys;
import org.example.authmodule.entity.User;
import org.example.authmodule.support.JwtTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class JwtSignerTest {

    private JwtParser parser;
    private JwtSigner signer;
    private User user;

    @BeforeEach
    void setUp() {
        JwtKeys keys = JwtTestSupport.defaultKeys();
        parser = JwtTestSupport.defaultParser();
        signer = new JwtSigner(keys, Clock.systemUTC());
        user = JwtTestSupport.activeUser();
    }

    @Test
    void signsAccessTokenWithExpectedClaims() {
        String token = signer.sign(TokenKind.ACCESS, user);

        Claims claims = parser.parseSignedClaims(token).getPayload();

        assertThat(claims.getIssuer()).isEqualTo(JwtTestSupport.ISSUER);
        assertThat(claims.getSubject()).isEqualTo(user.getEmail());
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.get(JwtClaimNames.TOKEN_TYPE, String.class)).isEqualTo("access");
        assertThat(claims.get(JwtClaimNames.USER_ID, String.class)).isEqualTo(user.getUserId().toString());
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    @Test
    void signsRefreshTokenWithSubjectEqualToUserId() {
        String token = signer.sign(TokenKind.REFRESH, user);

        Claims claims = parser.parseSignedClaims(token).getPayload();

        assertThat(claims.getSubject()).isEqualTo(user.getUserId().toString());
        assertThat(claims.get(JwtClaimNames.TOKEN_TYPE, String.class)).isEqualTo("refresh");
        assertThat(claims.get(JwtClaimNames.USER_ID, String.class)).isNull();
    }

    @Test
    void eachSignProducesUniqueJti() {
        String t1 = signer.sign(TokenKind.ACCESS, user);
        String t2 = signer.sign(TokenKind.ACCESS, user);

        String jti1 = parser.parseSignedClaims(t1).getPayload().getId();
        String jti2 = parser.parseSignedClaims(t2).getPayload().getId();

        assertThat(jti1).isNotEqualTo(jti2);
    }

    @Test
    void expiresInSecondsMatchesProperties() {
        int access = signer.expiresInSeconds(TokenKind.ACCESS);
        int refresh = signer.expiresInSeconds(TokenKind.REFRESH);

        assertThat(access).isEqualTo((int) (JwtTestSupport.ACCESS_EXP_MS / 1000));
        assertThat(refresh).isEqualTo((int) (JwtTestSupport.REFRESH_EXP_MS / 1000));
    }
}
