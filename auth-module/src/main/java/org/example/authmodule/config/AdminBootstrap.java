package org.example.authmodule.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.entity.Role;
import org.example.authmodule.entity.User;
import org.example.authmodule.properties.AuthAdminProperties;
import org.example.authmodule.repository.RoleRepository;
import org.example.authmodule.repository.UserRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;

/**
 * Создаёт служебного ADMIN-пользователя и роль при старте приложения, если
 * они ещё не существуют. Позволяет иметь входную точку для управления правами
 * на пустой БД.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminBootstrap implements ApplicationRunner {

    private final AuthAdminProperties properties;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (properties.email() == null || properties.email().isBlank()
                || properties.password() == null || properties.password().isBlank()) {
            log.warn("auth.admin.email/password не заданы — bootstrap ADMIN пропущен");
            return;
        }

        Role adminRole = roleRepository.findByRoleName(properties.roleName())
                .orElseGet(() -> {
                    Role r = new Role();
                    r.setRoleName(properties.roleName());
                    return roleRepository.save(r);
                });

        User admin = userRepository.findByEmail(properties.email())
                .orElseGet(() -> {
                    User u = new User();
                    u.setEmail(properties.email());
                    u.setFullName(properties.fullName() == null ? "Administrator" : properties.fullName());
                    u.setPasswordHash(passwordEncoder.encode(properties.password()));
                    u.setStatus(UserStatus.ACTIVE);
                    u.setFailedLoginAttempts(0);
                    u.setRoles(new ArrayList<>());
                    u.setGroups(new ArrayList<>());
                    return userRepository.save(u);
                });

        if (admin.getRoles() == null) {
            admin.setRoles(new ArrayList<>());
        }

        boolean hasAdminRole = admin.getRoles().stream()
                .anyMatch(r -> r.getRoleId().equals(adminRole.getRoleId()));
        if (!hasAdminRole) {
            admin.getRoles().add(adminRole);
            userRepository.save(admin);
            log.info("ADMIN-роль привязана к {}", admin.getEmail());
        }
    }
}
