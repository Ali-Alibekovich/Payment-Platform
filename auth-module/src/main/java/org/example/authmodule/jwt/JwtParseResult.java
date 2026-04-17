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

    /**
     * Токен невалиден: подпись, срок действия или формат.
     */
    record Invalid(String reason) implements JwtParseResult {
    }

    /**
     * Токен валиден криптографически, но имеет другой {@code typ}.
     */
    record TypeMismatch(String actual, TokenKind expected) implements JwtParseResult {
    }

    /**
     * @return claims, если результат успешный
     */
    default Optional<TokenClaims> asClaims() {
        return this instanceof Ok ok ? Optional.of(ok.claims()) : Optional.empty();
    }

    /**
     * Приводит claims к ожидаемому типу.
     *
     * @param type целевой класс claims
     * @param <T>  тип claims
     * @return claims требуемого типа или пустой optional
     */
    default <T extends TokenClaims> Optional<T> claimsAs(Class<T> type) {
        return asClaims().filter(type::isInstance).map(type::cast);
    }
}
