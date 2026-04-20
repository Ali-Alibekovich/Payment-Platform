package org.example.authmodule.dto.auth.response;

/**
 * Ответ на запрос авторизации
 *
 * @param accessToken      токен
 * @param refreshToken     refresh токен
 * @param expiresIn        время действия токена
 * @param refreshExpiresIn время действия refresh токена
 * @param tokenType        тип токена (Bearer)
 */
public record LoginResponse(
        String accessToken,
        String refreshToken,
        Integer expiresIn,
        Integer refreshExpiresIn,
        String tokenType
) {
}
