package org.example.authmodule.service;

import org.example.authmodule.dto.*;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.AccountLockedException;
import org.example.authmodule.exception.EmailAlreadyExistsException;
import org.example.authmodule.exception.InvalidCredentialsException;
import org.example.authmodule.mapper.UserMapper;
import org.example.authmodule.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final int maxFailedAttempts;
    private final long lockDurationMinutes;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       UserMapper userMapper,
                       JwtService jwtService,
                       @Value("${auth.login.max-failed-attempts}") int maxFailedAttempts,
                       @Value("${auth.login.lock-duration-minutes}") long lockDurationMinutes) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.jwtService = jwtService;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDurationMinutes = lockDurationMinutes;
    }

    public UserResponseDto register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException();
        }

        User user = new User();
        user.setEmail(request.email());
        user.setFullName(request.fullName());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setStatus(UserStatus.ACTIVE);
        user.setCreatedAt(Instant.now());

        user.setFailedLoginAttempts(0);

        User savedUser = userRepository.save(user);

        return userMapper.toDto(savedUser);
    }

    @Transactional(noRollbackFor = {InvalidCredentialsException.class, AccountLockedException.class})
    public LoginResponseDto login(LoginRequest request) {

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);

        Instant now = Instant.now();
        if (user.getLockedUntil() != null) {
            if (now.isBefore(user.getLockedUntil())) {
                throw new AccountLockedException(lockDurationMinutes);
            }
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);
            if (attempts >= maxFailedAttempts) {
                user.setLockedUntil(now.plus(lockDurationMinutes, ChronoUnit.MINUTES));
                userRepository.save(user);
                throw new AccountLockedException(lockDurationMinutes);
            }
            userRepository.save(user);
            int remaining = maxFailedAttempts - attempts;
            throw new InvalidCredentialsException(remaining);
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new LoginResponseDto(
                accessToken,
                refreshToken,
                jwtService.getAccessTokenExpirationSeconds(),
                "Bearer"
        );
    }
}
