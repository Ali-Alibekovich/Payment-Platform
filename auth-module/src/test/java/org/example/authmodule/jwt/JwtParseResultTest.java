package org.example.authmodule.jwt;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class JwtParseResultTest {

    private static final AccessClaims ACCESS =
            new AccessClaims("jti-1", "u@e.com", "user-1", Set.of(), Instant.now().plusSeconds(60));
    private static final RefreshClaims REFRESH =
            new RefreshClaims("jti-2", "user-2", Instant.now().plusSeconds(600));

    @Test
    void okExposesClaims() {
        JwtParseResult result = new JwtParseResult.Ok(ACCESS);

        assertThat(result.asClaims()).contains(ACCESS);
        assertThat(result.claimsAs(AccessClaims.class)).contains(ACCESS);
    }

    @Test
    void claimsAsReturnsEmptyWhenWrongType() {
        JwtParseResult result = new JwtParseResult.Ok(ACCESS);

        assertThat(result.claimsAs(RefreshClaims.class)).isEmpty();
    }

    @Test
    void claimsAsCastsToRefreshWhenRefresh() {
        JwtParseResult result = new JwtParseResult.Ok(REFRESH);

        assertThat(result.claimsAs(RefreshClaims.class)).contains(REFRESH);
        assertThat(result.claimsAs(AccessClaims.class)).isEmpty();
    }

    @Test
    void invalidHasNoClaims() {
        JwtParseResult result = new JwtParseResult.Invalid("bad signature");

        assertThat(result.asClaims()).isEqualTo(Optional.empty());
        assertThat(result.claimsAs(AccessClaims.class)).isEmpty();
    }

    @Test
    void typeMismatchHasNoClaims() {
        JwtParseResult result = new JwtParseResult.TypeMismatch("refresh", TokenKind.ACCESS);

        assertThat(result.asClaims()).isEmpty();
        assertThat(result.claimsAs(AccessClaims.class)).isEmpty();
    }
}
