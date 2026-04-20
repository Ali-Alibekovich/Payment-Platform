package org.example.authmodule.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.example.authmodule.dto.UserStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Сущность для хранения записи о пользователях
 */
@Getter
@Setter
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    private UUID userId;

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

    //Groups
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_group",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id")
    )
    private List<Group> groups;

    //Roles
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private List<Role> roles;

    @Column
    private Instant lockedUntil;

    @Column
    private Instant anonymizedAt;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();
}