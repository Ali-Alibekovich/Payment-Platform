package org.example.authmodule.dto.auth.response;

/**
 * Внутренняя пара токенов до разделения на JSON + Set-Cookie.
 */
public record IssuedTokenPair(
        String accessToken,
        String refreshToken,
        int expiresIn,
        int refreshExpiresIn,
        String tokenType
) {

    public LoginResponse toBody() {
        return new LoginResponse(accessToken, refreshToken, expiresIn, refreshExpiresIn, tokenType);
    }
}
