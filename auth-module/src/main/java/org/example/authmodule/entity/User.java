package org.example.authmodule.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.example.authmodule.dto.UserStatus;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private String fullName;

    @Enumerated(EnumType.STRING)
    private UserStatus status;

    @Column(nullable = false)
    private Integer failedLoginAttempts = 0;

    @Column
    private Instant lockedUntil;

    @Column
    private Instant anonymizedAt;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();
}