package org.example.authmodule.dto;

/**
 * Запрос на получени токена по refresh токену
 *
 * @param refreshToken
 */
public record RefreshTokenRequest(String refreshToken) {
}
