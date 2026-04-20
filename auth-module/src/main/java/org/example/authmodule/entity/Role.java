package org.example.authmodule.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue
    private UUID roleId;

    @Column(nullable = false, unique = true)
    private String roleName;
}
