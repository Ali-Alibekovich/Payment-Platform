package org.example.authmodule.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * Ответ на запрос регистрации
 *
 * @param id        иднетификатор пользователя
 * @param email     почта пользователя
 * @param fullName  имя пользователя
 * @param status    статус аккаунта
 * @param createdAt время создания аккаунта
 */
public record UserResponseDto(
        UUID id,
        String email,
        String fullName,
        UserStatus status,
        Instant createdAt
) {
}