package org.example.authmodule.config.security;

import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.security.AccessTokenTypeValidator;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AccessTokenTypeValidatorTest {

    private final AccessTokenTypeValidator validator = new AccessTokenTypeValidator();

    @Test
    void successWhenTypIsAccess() {
        OAuth2TokenValidatorResult result = validator.validate(jwtWithTyp("access"));

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void failsWhenTypIsRefresh() {
        OAuth2TokenValidatorResult result = validator.validate(jwtWithTyp("refresh"));

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .anyMatch(e -> e.getDescription().contains("typ=refresh"));
    }

    @Test
    void failsWhenTypIsMissing() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "HS256")
                .claim("sub", "x")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThat(validator.validate(jwt).hasErrors()).isTrue();
    }

    private static Jwt jwtWithTyp(String typ) {
        return Jwt.withTokenValue("t")
                .header("alg", "HS256")
                .claims(c -> c.putAll(Map.of(
                        "sub", "subject",
                        JwtClaimNames.TOKEN_TYPE, typ
                )))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }
}
