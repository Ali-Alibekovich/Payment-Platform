package org.example.authmodule.service;

import lombok.extern.slf4j.Slf4j;
import org.example.authmodule.config.logging.LogSanitizer;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.dto.auth.request.LoginRequest;
import org.example.authmodule.dto.auth.request.RegisterRequest;
import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.dto.auth.response.UserResponse;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.mapper.UserMapper;
import org.example.authmodule.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * Сервис авторизации
 */
@Slf4j
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final SessionTokensService sessionTokens;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final int maxFailedAttempts;
    private final long lockDurationMinutes;

    public AuthService(
            UserRepository userRepository,
            SessionTokensService sessionTokens,
            PasswordEncoder passwordEncoder,
            UserMapper userMapper,
            @Value("${auth.login.max-failed-attempts}") int maxFailedAttempts,
            @Value("${auth.login.lock-duration-minutes}") long lockDurationMinutes
    ) {
        this.userRepository = userRepository;
        this.sessionTokens = sessionTokens;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDurationMinutes = lockDurationMinutes;
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String maskedEmail = LogSanitizer.maskEmail(request.email());
        if (userRepository.existsByEmail(request.email())) {
            log.warn("Register rejected: email already exists email={}", maskedEmail);
            throw new BusinessException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        User user = new User();
        user.setEmail(request.email());
        user.setFullName(request.fullName());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setStatus(UserStatus.ACTIVE);
        user.setCreatedAt(Instant.now());
        user.setFailedLoginAttempts(0);

        User savedUser = userRepository.save(user);
        log.info("User registered userId={} email={}", savedUser.getUserId(), maskedEmail);
        return userMapper.toDto(savedUser);
    }

    @Transactional(noRollbackFor = BusinessException.class)
    public IssuedTokenPair login(LoginRequest request) {
        String maskedEmail = LogSanitizer.maskEmail(request.email());
        User user = userRepository.findByEmailForUpdate(request.email())
                .orElseThrow(() -> {
                    log.warn("Login failed: unknown email email={}", maskedEmail);
                    return new BusinessException(ErrorCode.INVALID_CREDENTIALS);
                });

        Instant now = Instant.now();
        if (user.getLockedUntil() != null) {
            if (now.isBefore(user.getLockedUntil())) {
                log.warn("Login blocked: account locked userId={} until={}", user.getUserId(), user.getLockedUntil());
                throw new BusinessException(
                        ErrorCode.ACCOUNT_TEMPORARILY_LOCKED,
                        "Вход временно заблокирован. Повторите через " + lockDurationMinutes + " мин.",
                        Map.of("retryAfterMinutes", lockDurationMinutes)
                );
            }
            log.info("Lock expired, resetting counter userId={}", user.getUserId());
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= maxFailedAttempts) {
                user.setLockedUntil(now.plus(lockDurationMinutes, ChronoUnit.MINUTES));
                userRepository.save(user);
                log.warn("Account locked after {} failed attempts userId={} lockDurationMinutes={}",
                        attempts, user.getUserId(), lockDurationMinutes);
                throw new BusinessException(
                        ErrorCode.ACCOUNT_TEMPORARILY_LOCKED,
                        "Вход временно заблокирован. Повторите через " + lockDurationMinutes + " мин.",
                        Map.of("retryAfterMinutes", lockDurationMinutes)
                );
            }
            userRepository.save(user);
            int remaining = maxFailedAttempts - attempts;
            log.warn("Login failed: bad password userId={} attempt={} remaining={}",
                    user.getUserId(), attempts, remaining);
            throw new BusinessException(
                    ErrorCode.INVALID_CREDENTIALS,
                    "Неверный пароль. Осталось попыток: " + remaining,
                    Map.of("remainingAttempts", remaining)
            );
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        log.info("Login success userId={}", user.getUserId());
        return sessionTokens.issuePair(user);
    }

    public IssuedTokenPair refresh(String refreshToken) {
        log.debug("Refresh requested");
        return sessionTokens.rotateRefreshToken(refreshToken);
    }

    public void logout(String accessToken, String refreshToken) {
        log.debug("Logout requested");
        sessionTokens.revokeAccessAndRefresh(accessToken, refreshToken);
    }
}
