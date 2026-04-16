package org.example.authmodule.jwt;

import java.util.Optional;

/**
 * Результат валидации JWT. Позволяет отличить битую подпись/просрочку от
 * «подпись валидна, но тип не тот».
 */
public sealed interface JwtParseResult
        permits JwtParseResult.Ok, JwtParseResult.Invalid, JwtParseResult.TypeMismatch {

    record Ok(TokenClaims claims) implements JwtParseResult {
    }

    record Invalid(String reason) implements JwtParseResult {
    }

    record TypeMismatch(String actual, TokenKind expected) implements JwtParseResult {
    }

    default Optional<TokenClaims> asClaims() {
        return this instanceof Ok ok ? Optional.of(ok.claims()) : Optional.empty();
    }

    default <T extends TokenClaims> Optional<T> claimsAs(Class<T> type) {
        return asClaims().filter(type::isInstance).map(type::cast);
    }
}
