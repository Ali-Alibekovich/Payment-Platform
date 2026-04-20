package org.example.authmodule.dto.auth.response;

import org.example.authmodule.dto.UserStatus;

import java.time.Instant;
import java.util.UUID;

/**
 * Ответ на запрос регистрации
 *
 * @param userId        иднетификатор пользователя
 * @param email     почта пользователя
 * @param fullName  имя пользователя
 * @param status    статус аккаунта
 * @param createdAt время создания аккаунта
 */
public record UserResponse(
        UUID userId,
        String email,
        String fullName,
        UserStatus status,
        Instant createdAt
) {
}