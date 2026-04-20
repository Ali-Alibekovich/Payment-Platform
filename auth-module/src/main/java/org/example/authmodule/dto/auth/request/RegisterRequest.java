package org.example.authmodule.dto.auth.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Запрос на регистрацию
 *
 * @param email    почта
 * @param password пароль
 * @param fullName имя
 */
public record RegisterRequest(
        @NotBlank
        @Email(message = "Invalid email format")
        String email,

        @NotBlank
        @Size(min = 8, message = "Password must be at least 8 characters")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&]).+$",
                message = "Password must contain 1 uppercase letter, 1 digit, and 1 special character"
        )
        String password,

        @NotBlank
        @Size(min = 2, max = 255, message = "Full name must be between 2 and 255 characters")
        String fullName

) {
}