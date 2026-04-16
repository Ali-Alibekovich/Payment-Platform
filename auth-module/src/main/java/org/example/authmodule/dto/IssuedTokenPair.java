package org.example.authmodule.dto;

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

    public LoginResponseDto toBody() {
        return new LoginResponseDto(accessToken, refreshToken, expiresIn, refreshExpiresIn, tokenType);
    }
}
