package org.example.authmodule.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Валидирует JWT и проецирует его в типизированные {@link TokenClaims}.
 * Возвращает sealed {@link JwtParseResult}, чтобы вызывающий мог различать
 * «битый» токен и «подпись ок, но не тот тип».
 */
@Component
public class JwtVerifier {

    private static final Logger log = LoggerFactory.getLogger(JwtVerifier.class);

    private final JwtKeys keys;

    public JwtVerifier(JwtKeys keys) {
        this.keys = keys;
    }

    public JwtParseResult verify(String token, TokenKind expected) {
        if (token == null || token.isBlank()) {
            return new JwtParseResult.Invalid("empty token");
        }
        try {
            Claims claims = keys.parser().parseSignedClaims(token).getPayload();
            String actualTyp = claims.get(JwtClaimNames.TOKEN_TYPE, String.class);
            if (actualTyp == null || !actualTyp.equals(expected.claimValue())) {
                return new JwtParseResult.TypeMismatch(actualTyp, expected);
            }
            if (claims.getId() == null || claims.getId().isBlank()) {
                return new JwtParseResult.Invalid("missing jti");
            }
            return new JwtParseResult.Ok(expected.project(claims));
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            return new JwtParseResult.Invalid(e.getMessage());
        }
    }
}
