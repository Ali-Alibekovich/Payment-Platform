package org.example.authmodule.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "groups")
public class Group {

    @Id
    @GeneratedValue
    private UUID groupId;

    @Column(nullable = false, unique = true)
    private String groupName;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "group_role",
            joinColumns = @JoinColumn(name = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private List<Role> roles;

    @ManyToMany(mappedBy = "groups")
    private List<User> users;
}
