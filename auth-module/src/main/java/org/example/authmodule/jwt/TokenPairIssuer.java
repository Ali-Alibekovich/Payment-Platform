package org.example.authmodule.jwt;

import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.entity.User;
import org.springframework.stereotype.Component;

/**
 * Фасад выпуска пары токенов (access + refresh) для пользователя.
 */
@Component
public class TokenPairIssuer {

    private static final String TOKEN_TYPE = "Bearer";

    private final JwtSigner signer;

    public TokenPairIssuer(JwtSigner signer) {
        this.signer = signer;
    }

    /**
     * Выпускает новую пару токенов и метаданные времени жизни.
     *
     * @param user пользователь, для которого выпускаются токены
     * @return структура с access/refresh токенами и временем жизни
     */
    public IssuedTokenPair issue(User user) {
        return new IssuedTokenPair(
                signer.sign(TokenKind.ACCESS, user),
                signer.sign(TokenKind.REFRESH, user),
                signer.expiresInSeconds(TokenKind.ACCESS),
                signer.expiresInSeconds(TokenKind.REFRESH),
                TOKEN_TYPE
        );
    }
}
