package org.example.authmodule.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Параметры служебного ADMIN-пользователя, создаваемого при старте приложения.
 */
@ConfigurationProperties(prefix = "auth.admin")
public record AuthAdminProperties(
        String email,
        String password,
        String fullName,
        String roleName
) {
    public AuthAdminProperties {
        if (roleName == null || roleName.isBlank()) {
            roleName = "ADMIN";
        }
    }
}
