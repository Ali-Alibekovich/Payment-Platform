package org.example.authmodule.config.security;

import org.example.authcommon.security.JtiBlacklistStore;
import org.example.authcommon.security.JtiBlacklistValidator;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JtiBlacklistValidatorTest {

    private final JtiBlacklistStore blacklist = mock(JtiBlacklistStore.class);
    private final JtiBlacklistValidator validator = new JtiBlacklistValidator(blacklist);

    @Test
    void successWhenJtiPresentAndNotRevoked() {
        when(blacklist.isRevoked("jti-1")).thenReturn(false);

        OAuth2TokenValidatorResult result = validator.validate(jwtWithJti());

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void failsWhenJtiRevoked() {
        when(blacklist.isRevoked("jti-1")).thenReturn(true);

        OAuth2TokenValidatorResult result = validator.validate(jwtWithJti());

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .anyMatch(e -> e.getDescription().contains("revoked"));
    }

    @Test
    void failsWhenJtiMissing() {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "HS256")
                .claim("sub", "user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .anyMatch(e -> e.getDescription().contains("Missing jti"));
    }

    private static Jwt jwtWithJti() {
        return Jwt.withTokenValue("t")
                .header("alg", "HS256")
                .jti("jti-1")
                .claim("sub", "user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }
}
