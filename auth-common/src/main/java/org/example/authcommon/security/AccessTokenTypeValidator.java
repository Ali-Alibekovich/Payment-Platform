package org.example.authcommon.security;

import org.example.authcommon.jwt.JwtClaimNames;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Objects;

/**
 * Пропускает только access-токены: claim {@code typ} должен равняться
 * {@code access}. Нужно, чтобы refresh-токен нельзя было предъявить как Bearer
 * для доступа к защищённым эндпоинтам.
 */
public class AccessTokenTypeValidator implements OAuth2TokenValidator<Jwt> {

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String actual = jwt.getClaimAsString(JwtClaimNames.TOKEN_TYPE);
        if (!Objects.equals(actual, JwtClaimNames.TYPE_ACCESS)) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "Expected access token, got typ=" + actual,
                    null
            ));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
