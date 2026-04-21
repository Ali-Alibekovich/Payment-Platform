package org.example.authmodule.repository;

import org.example.authmodule.entity.RefreshTokens;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokensRepository extends JpaRepository<RefreshTokens, UUID> {

    Optional<RefreshTokens> findByTokenHash(String tokenHash);

    @Modifying
    @Query("""
            update RefreshTokens r
               set r.status = org.example.authmodule.entity.Status.REVOKED
             where r.tokenFamilyId = :familyId
               and r.status = org.example.authmodule.entity.Status.ACTIVE
            """)
    int revokeFamily(@Param("familyId") UUID familyId);
}
