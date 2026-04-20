package org.example.authmodule.repository;

import org.example.authmodule.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface GroupRepository extends JpaRepository<Group, UUID> {

    boolean existsByGroupName(String name);
}
