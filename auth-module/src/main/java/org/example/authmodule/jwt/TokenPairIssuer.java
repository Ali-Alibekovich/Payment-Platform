package org.example.authmodule.jwt;

import org.example.authmodule.dto.IssuedTokenPair;
import org.example.authmodule.entity.User;
import org.springframework.stereotype.Component;

@Component
public class TokenPairIssuer {

    private static final String TOKEN_TYPE = "Bearer";

    private final JwtSigner signer;

    public TokenPairIssuer(JwtSigner signer) {
        this.signer = signer;
    }

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
