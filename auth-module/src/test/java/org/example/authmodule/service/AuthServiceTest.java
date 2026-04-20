package org.example.authmodule.service;

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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    private UserRepository userRepository;
    private SessionTokensService sessionTokens;
    private PasswordEncoder passwordEncoder;
    private UserMapper userMapper;
    private AuthService authService;

    private static final int MAX_FAILED = 3;
    private static final long LOCK_MIN = 15;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        sessionTokens = mock(SessionTokensService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        userMapper = mock(UserMapper.class);
        authService = new AuthService(userRepository, sessionTokens, passwordEncoder, userMapper, MAX_FAILED, LOCK_MIN);
    }

    @Test
    void registerCreatesUserWithEncodedPasswordAndActiveStatus() {
        RegisterRequest req = new RegisterRequest("u@example.com", "Password1!", "Full Name");
        when(userRepository.existsByEmail("u@example.com")).thenReturn(false);
        when(passwordEncoder.encode("Password1!")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
        UserResponse dto = new UserResponse(UUID.randomUUID(), "u@example.com", "Full Name", UserStatus.ACTIVE, Instant.now());
        when(userMapper.toDto(any(User.class))).thenReturn(dto);

        UserResponse result = authService.register(req);

        assertThat(result).isSameAs(dto);
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getEmail()).isEqualTo("u@example.com");
        assertThat(saved.getPasswordHash()).isEqualTo("hashed");
        assertThat(saved.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(saved.getFailedLoginAttempts()).isZero();
    }

    @Test
    void registerThrowsWhenEmailExists() {
        RegisterRequest req = new RegisterRequest("u@example.com", "Password1!", "Full Name");
        when(userRepository.existsByEmail("u@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS);

        verify(userRepository, never()).save(any());
    }

    @Test
    void loginThrowsInvalidCredentialsWhenUserMissing() {
        when(userRepository.findByEmailForUpdate("x@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("x@example.com", "Password1!")))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_CREDENTIALS);
    }

    @Test
    void loginThrowsLockedWhenStillLocked() {
        User user = activeUser();
        user.setLockedUntil(Instant.now().plusSeconds(60));
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(new LoginRequest(user.getEmail(), "Password1!")))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.ACCOUNT_TEMPORARILY_LOCKED);

        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void loginResetsLockWhenLockExpired() {
        User user = activeUser();
        user.setLockedUntil(Instant.now().minusSeconds(60));
        user.setFailedLoginAttempts(MAX_FAILED);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Password1!", user.getPasswordHash())).thenReturn(true);
        IssuedTokenPair pair = mock(IssuedTokenPair.class);
        when(sessionTokens.issuePair(user)).thenReturn(pair);

        IssuedTokenPair result = authService.login(new LoginRequest(user.getEmail(), "Password1!"));

        assertThat(result).isSameAs(pair);
        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
    }

    @Test
    void loginIncrementsFailedAttemptsOnWrongPassword() {
        User user = activeUser();
        user.setFailedLoginAttempts(0);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Password1!", user.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest(user.getEmail(), "Password1!")))
                .isInstanceOf(BusinessException.class)
                .satisfies(e -> {
                    BusinessException be = (BusinessException) e;
                    assertThat(be.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
                    assertThat(be.getDetails()).containsEntry("remainingAttempts", MAX_FAILED - 1);
                });

        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        verify(userRepository).save(user);
    }

    @Test
    void loginLocksAccountAfterMaxFailedAttempts() {
        User user = activeUser();
        user.setFailedLoginAttempts(MAX_FAILED - 1);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Password1!", user.getPasswordHash())).thenReturn(false);
        Instant before = Instant.now();

        assertThatThrownBy(() -> authService.login(new LoginRequest(user.getEmail(), "Password1!")))
                .isInstanceOf(BusinessException.class)
                .satisfies(e -> assertThat(((BusinessException) e).getErrorCode())
                        .isEqualTo(ErrorCode.ACCOUNT_TEMPORARILY_LOCKED));

        assertThat(user.getFailedLoginAttempts()).isEqualTo(MAX_FAILED);
        assertThat(user.getLockedUntil()).isAfter(before.plus(LOCK_MIN - 1, ChronoUnit.MINUTES));
        verify(userRepository).save(user);
    }

    @Test
    void loginSucceedsAndResetsCountersOnCorrectPassword() {
        User user = activeUser();
        user.setFailedLoginAttempts(2);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Password1!", user.getPasswordHash())).thenReturn(true);
        IssuedTokenPair pair = mock(IssuedTokenPair.class);
        when(sessionTokens.issuePair(user)).thenReturn(pair);

        IssuedTokenPair result = authService.login(new LoginRequest(user.getEmail(), "Password1!"));

        assertThat(result).isSameAs(pair);
        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
        verify(userRepository).save(user);
    }

    @Test
    void refreshDelegatesToSessionTokens() {
        IssuedTokenPair pair = mock(IssuedTokenPair.class);
        when(sessionTokens.rotateRefreshToken("rt")).thenReturn(pair);

        assertThat(authService.refresh("rt")).isSameAs(pair);
    }

    @Test
    void logoutDelegatesToSessionTokens() {
        authService.logout("at", "rt");

        verify(sessionTokens, times(1)).revokeAccessAndRefresh("at", "rt");
    }

    private static User activeUser() {
        User u = new User();
        u.setUserId(UUID.randomUUID());
        u.setEmail("u@example.com");
        u.setFullName("Full");
        u.setPasswordHash("hash");
        u.setStatus(UserStatus.ACTIVE);
        u.setFailedLoginAttempts(0);
        u.setCreatedAt(Instant.now());
        u.setUpdatedAt(Instant.now());
        return u;
    }
}
