package org.example.authmodule.jwt;

import org.example.authcommon.jwt.JwtKeys;
import org.example.authcommon.jwt.JwtProperties;
import org.example.authmodule.support.JwtTestSupport;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtKeysTest {

    @Test
    void buildsKeyFromNonBlankSecret() {
        JwtKeys keys = JwtTestSupport.defaultKeys();

        assertThat(keys.signingKey()).isNotNull();
        assertThat(keys.properties().issuer()).isEqualTo(JwtTestSupport.ISSUER);
    }

    @Test
    void throwsWhenSecretIsNull() {
        JwtProperties props = new JwtProperties(null, "iss", 5, 1000, 2000);
        assertThatThrownBy(() -> new JwtKeys(props))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("jwt.secret");
    }

    @Test
    void throwsWhenSecretIsBlank() {
        JwtProperties props = new JwtProperties("   ", "iss", 5, 1000, 2000);
        assertThatThrownBy(() -> new JwtKeys(props))
                .isInstanceOf(IllegalStateException.class);
    }
}
