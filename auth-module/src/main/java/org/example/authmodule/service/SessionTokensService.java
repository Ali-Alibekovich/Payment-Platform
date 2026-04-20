package org.example.authmodule.service;

import org.example.authcommon.security.JtiBlacklistStore;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.jwt.*;
import org.example.authmodule.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Сервис для работы с токеном
 * Сценарии: выдача пары токенов, ротация refresh, отзыв при logout.
 */
@Service
public class SessionTokensService {

    private final TokenPairIssuer tokenPairIssuer;
    private final JwtVerifier jwtVerifier;
    private final JtiBlacklistStore blacklist;
    private final UserRepository userRepository;
    private final long lockDurationMinutes;

    public SessionTokensService(
            TokenPairIssuer tokenPairIssuer,
            JwtVerifier jwtVerifier,
            JtiBlacklistStore blacklist,
            UserRepository userRepository,
            @Value("${auth.login.lock-duration-minutes}") long lockDurationMinutes
    ) {
        this.tokenPairIssuer = tokenPairIssuer;
        this.jwtVerifier = jwtVerifier;
        this.blacklist = blacklist;
        this.userRepository = userRepository;
        this.lockDurationMinutes = lockDurationMinutes;
    }

    /**
     * Создание токенов access, refresh
     *
     * @param user пользователь для которого выдается токен
     * @return пара токенов
     */
    public IssuedTokenPair issuePair(User user) {
        return tokenPairIssuer.issue(user);
    }

    /**
     * Выдача новой пары токенов (access, refresh) и добавление нынешних в blacklist
     *
     * @param rawRefreshToken refresh токен
     * @return новая пара токенов (access, refresh)
     */
    public IssuedTokenPair rotateRefreshToken(String rawRefreshToken) {
        RefreshClaims claims = jwtVerifier.verify(rawRefreshToken, TokenKind.REFRESH)
                .claimsAs(RefreshClaims.class)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN));

        if (!blacklist.tryRevoke(claims.jti(), JwtTtl.secondsUntil(claims.expiresAt()))) {
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
        }

        UUID userId;
        try {
            userId = UUID.fromString(claims.userId());
        } catch (IllegalArgumentException e) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        Instant now = Instant.now();
        if (user.getLockedUntil() != null && now.isBefore(user.getLockedUntil())) {
            throw new BusinessException(
                    ErrorCode.ACCOUNT_TEMPORARILY_LOCKED,
                    "Вход временно заблокирован. Повторите через " + lockDurationMinutes + " мин.",
                    Map.of("retryAfterMinutes", lockDurationMinutes)
            );
        }

        return tokenPairIssuer.issue(user);
    }

    /**
     * Метод для добавления токенов в blacklist
     *
     * @param rawAccessToken  access токен
     * @param rawRefreshToken refresh токен
     */
    public void revokeAccessAndRefresh(String rawAccessToken, String rawRefreshToken) {
        revokeIfPresent(rawAccessToken, TokenKind.ACCESS);
        revokeIfPresent(rawRefreshToken, TokenKind.REFRESH);
    }

    private void revokeIfPresent(String rawToken, TokenKind kind) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        jwtVerifier.verify(rawToken, kind).asClaims().ifPresent(c ->
                blacklist.revokeUntilExpiry(c.jti(), JwtTtl.secondsUntil(c.expiresAt()))
        );
    }
}
