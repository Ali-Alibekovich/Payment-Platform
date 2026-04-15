package org.example.authmodule.dto;

import java.time.Instant;
import java.util.UUID;

public record UserResponseDto(
        UUID id,
        String email,
        String fullName,
        UserStatus status,
        Instant createdAt
) {
}