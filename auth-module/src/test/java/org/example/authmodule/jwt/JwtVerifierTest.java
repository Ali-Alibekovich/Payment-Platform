package org.example.authmodule.jwt;

import io.jsonwebtoken.Jwts;
import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.jwt.JwtKeys;
import org.example.authcommon.jwt.JwtProperties;
import org.example.authmodule.entity.User;
import org.example.authmodule.support.JwtTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtVerifierTest {

    private JwtKeys keys;
    private JwtSigner signer;
    private JwtVerifier verifier;
    private User user;

    @BeforeEach
    void setUp() {
        keys = JwtTestSupport.defaultKeys();
        signer = new JwtSigner(keys, Clock.systemUTC());
        verifier = new JwtVerifier(keys, Clock.systemUTC());
        user = JwtTestSupport.activeUser();
    }

    @Test
    void verifiesValidAccessToken() {
        String token = signer.sign(TokenKind.ACCESS, user);

        JwtParseResult result = verifier.verify(token, TokenKind.ACCESS);

        assertThat(result).isInstanceOf(JwtParseResult.Ok.class);
        AccessClaims claims = result.claimsAs(AccessClaims.class).orElseThrow();
        assertThat(claims.userId()).isEqualTo(user.getUserId().toString());
        assertThat(claims.email()).isEqualTo(user.getEmail());
        assertThat(claims.jti()).isNotBlank();
    }

    @Test
    void verifiesValidRefreshToken() {
        String token = signer.sign(TokenKind.REFRESH, user);

        JwtParseResult result = verifier.verify(token, TokenKind.REFRESH);

        RefreshClaims claims = result.claimsAs(RefreshClaims.class).orElseThrow();
        assertThat(claims.userId()).isEqualTo(user.getUserId().toString());
    }

    @Test
    void rejectsBlankAndNullTokens() {
        assertThat(verifier.verify("", TokenKind.ACCESS)).isInstanceOf(JwtParseResult.Invalid.class);
        assertThat(verifier.verify("   ", TokenKind.ACCESS)).isInstanceOf(JwtParseResult.Invalid.class);
        assertThat(verifier.verify(null, TokenKind.ACCESS)).isInstanceOf(JwtParseResult.Invalid.class);
    }

    @Test
    void rejectsGarbageString() {
        assertThat(verifier.verify("not-a-jwt", TokenKind.ACCESS))
                .isInstanceOf(JwtParseResult.Invalid.class);
    }

    @Test
    void rejectsTokenSignedWithDifferentSecret() {
        JwtProperties otherProps = new JwtProperties(
                "completely-different-secret-value",
                JwtTestSupport.ISSUER, 5,
                JwtTestSupport.ACCESS_EXP_MS, JwtTestSupport.REFRESH_EXP_MS);
        JwtKeys otherKeys = new JwtKeys(otherProps);
        String foreignToken = new JwtSigner(otherKeys, Clock.systemUTC()).sign(TokenKind.ACCESS, user);

        assertThat(verifier.verify(foreignToken, TokenKind.ACCESS))
                .isInstanceOf(JwtParseResult.Invalid.class);
    }

    @Test
    void rejectsTokenWithDifferentIssuer() {
        JwtProperties wrongIssuer = new JwtProperties(
                JwtTestSupport.SECRET, "other-issuer", 5,
                JwtTestSupport.ACCESS_EXP_MS, JwtTestSupport.REFRESH_EXP_MS);
        String token = new JwtSigner(new JwtKeys(wrongIssuer), Clock.systemUTC()).sign(TokenKind.ACCESS, user);

        assertThat(verifier.verify(token, TokenKind.ACCESS))
                .isInstanceOf(JwtParseResult.Invalid.class);
    }

    @Test
    void rejectsExpiredToken() {
        Clock baseClock = Clock.fixed(
                Instant.parse("2026-04-20T10:07:00Z"),
                ZoneOffset.UTC
        );
        JwtProperties shortLived = new JwtProperties(
                JwtTestSupport.SECRET, JwtTestSupport.ISSUER, 0, 1, 1);
        JwtKeys shortKeys = new JwtKeys(shortLived);
        String token = new JwtSigner(shortKeys, baseClock).sign(TokenKind.ACCESS, user);

        Clock futureClock = Clock.offset(baseClock, Duration.ofSeconds(10));
        JwtVerifier expiredVerifier = new JwtVerifier(shortKeys, futureClock);

        JwtParseResult result = expiredVerifier.verify(token, TokenKind.ACCESS);

        assertThat(result).isInstanceOf(JwtParseResult.Invalid.class);
    }

    @Test
    void returnsTypeMismatchWhenRefreshPresentedAsAccess() {
        String refresh = signer.sign(TokenKind.REFRESH, user);

        JwtParseResult result = verifier.verify(refresh, TokenKind.ACCESS);

        assertThat(result).isInstanceOf(JwtParseResult.TypeMismatch.class);
        JwtParseResult.TypeMismatch mismatch = (JwtParseResult.TypeMismatch) result;
        assertThat(mismatch.actual()).isEqualTo("refresh");
        assertThat(mismatch.expected()).isEqualTo(TokenKind.ACCESS);
    }

    @Test
    void rejectsTokenWithoutJti() {
        String noJti = Jwts.builder()
                .issuer(JwtTestSupport.ISSUER)
                .subject(user.getEmail())
                .claim(JwtClaimNames.TOKEN_TYPE, "access")
                .claim(JwtClaimNames.USER_ID, user.getUserId().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(keys.signingKey())
                .compact();

        JwtParseResult result = verifier.verify(noJti, TokenKind.ACCESS);

        assertThat(result).isInstanceOf(JwtParseResult.Invalid.class);
        assertThat(((JwtParseResult.Invalid) result).reason()).contains("jti");
    }

    @Test
    void rejectsTokenWithoutTypeClaim() {
        String noTyp = Jwts.builder()
                .issuer(JwtTestSupport.ISSUER)
                .id(UUID.randomUUID().toString())
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(keys.signingKey())
                .compact();

        JwtParseResult result = verifier.verify(noTyp, TokenKind.ACCESS);

        assertThat(result).isInstanceOf(JwtParseResult.TypeMismatch.class);
    }
}
