package org.example.authmodule.repository;

import jakarta.persistence.LockModeType;
import org.example.authmodule.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);

    /**
     * Берёт пользователя под пессимистичной блокировкой на запись.
     * Сериализует конкурентные логины одного e-mail, чтобы инкремент
     * {@code failedLoginAttempts} не терялся из-за race condition read-modify-write.
     * Должен вызываться в границах транзакции.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.email = :email")
    Optional<User> findByEmailForUpdate(@Param("email") String email);
}
