package org.example.authmodule.jwt;

import io.jsonwebtoken.JwtParser;
import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.jwt.JwtKeys;
import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.entity.User;
import org.example.authmodule.support.JwtTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;

class TokenPairIssuerTest {

    private TokenPairIssuer issuer;
    private JwtParser parser;
    private User user;

    @BeforeEach
    void setUp() {
        JwtKeys keys = JwtTestSupport.defaultKeys();
        parser = JwtTestSupport.defaultParser();
        issuer = new TokenPairIssuer(new JwtSigner(keys, Clock.systemUTC()));
        user = JwtTestSupport.activeUser();
    }

    @Test
    void issuesPairWithBearerType() {
        IssuedTokenPair pair = issuer.issue(user);

        assertThat(pair.tokenType()).isEqualTo("Bearer");
        assertThat(pair.accessToken()).isNotBlank();
        assertThat(pair.refreshToken()).isNotBlank();
        assertThat(pair.accessToken()).isNotEqualTo(pair.refreshToken());
    }

    @Test
    void expiresInMatchesProperties() {
        IssuedTokenPair pair = issuer.issue(user);

        assertThat(pair.expiresIn()).isEqualTo((int) (JwtTestSupport.ACCESS_EXP_MS / 1000));
        assertThat(pair.refreshExpiresIn()).isEqualTo((int) (JwtTestSupport.REFRESH_EXP_MS / 1000));
    }

    @Test
    void accessTokenHasAccessTypeClaim() {
        IssuedTokenPair pair = issuer.issue(user);

        var accessClaims = parser.parseSignedClaims(pair.accessToken()).getPayload();
        var refreshClaims = parser.parseSignedClaims(pair.refreshToken()).getPayload();

        assertThat(accessClaims.get(JwtClaimNames.TOKEN_TYPE, String.class)).isEqualTo("access");
        assertThat(refreshClaims.get(JwtClaimNames.TOKEN_TYPE, String.class)).isEqualTo("refresh");
    }
}
