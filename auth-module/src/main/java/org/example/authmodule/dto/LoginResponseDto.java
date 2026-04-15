package org.example.authmodule.dto;

public record LoginResponseDto(String accessToken, String refreshToken, Integer expiresIn, String tokenType) {
}
