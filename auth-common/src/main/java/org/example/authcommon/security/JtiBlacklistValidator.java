package org.example.authcommon.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Отбивает отозванные токены: смотрит jti в {@link JtiBlacklistStore}.
 * Нужно, чтобы logout реально инвалидировал access-токен до его естественного
 * истечения.
 */
public class JtiBlacklistValidator implements OAuth2TokenValidator<Jwt> {

    private final JtiBlacklistStore blacklist;

    public JtiBlacklistValidator(JtiBlacklistStore blacklist) {
        this.blacklist = blacklist;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String jti = jwt.getId();
        if (jti == null || jti.isBlank()) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token", "Missing jti claim", null
            ));
        }
        if (blacklist.isRevoked(jti)) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token", "Access token revoked", null
            ));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
