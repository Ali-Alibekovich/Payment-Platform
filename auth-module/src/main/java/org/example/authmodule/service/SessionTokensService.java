package org.example.authmodule.service;

import lombok.extern.slf4j.Slf4j;
import org.example.authcommon.security.JtiBlacklistStore;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.entity.RefreshTokens;
import org.example.authmodule.entity.Status;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.jwt.*;
import org.example.authmodule.repository.RefreshTokensRepository;
import org.example.authmodule.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/**
 * Сервис для работы с токеном
 * Сценарии: выдача пары токенов, ротация refresh, отзыв при logout.
 */
@Slf4j
@Service
public class SessionTokensService {

    private final TokenPairIssuer tokenPairIssuer;
    private final JwtVerifier jwtVerifier;
    private final JtiBlacklistStore blacklist;
    private final UserRepository userRepository;
    private final RefreshTokensRepository refreshTokensRepository;
    private final TransactionTemplate requiresNewTx;
    private final long lockDurationMinutes;

    public SessionTokensService(
            TokenPairIssuer tokenPairIssuer,
            JwtVerifier jwtVerifier,
            JtiBlacklistStore blacklist,
            UserRepository userRepository,
            RefreshTokensRepository refreshTokensRepository,
            PlatformTransactionManager transactionManager,
            @Value("${auth.login.lock-duration-minutes}") long lockDurationMinutes
    ) {
        this.tokenPairIssuer = tokenPairIssuer;
        this.jwtVerifier = jwtVerifier;
        this.blacklist = blacklist;
        this.userRepository = userRepository;
        this.refreshTokensRepository = refreshTokensRepository;
        this.requiresNewTx = new TransactionTemplate(transactionManager);
        this.requiresNewTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.lockDurationMinutes = lockDurationMinutes;
    }

    /**
     * Создание токенов access, refresh и старт новой семьи refresh-токенов.
     * Первая запись в refresh_tokens создаётся именно здесь, чтобы последующий
     * rotate мог найти её по token_hash.
     *
     * @param user пользователь для которого выдается токен
     * @return пара токенов
     */
    @Transactional
    public IssuedTokenPair issuePair(User user) {
        IssuedTokenPair pair = tokenPairIssuer.issue(user);
        UUID familyId = UUID.randomUUID();
        persistRefreshToken(user.getUserId(), familyId, pair);
        log.info("Refresh token family started userId={} tokenFamilyId={}", user.getUserId(), familyId);
        return pair;
    }

    /**
     * Ротация refresh-токена.
     * При предъявлении уже использованного или отозванного токена вся цепочка
     * (token_family_id) помечается REVOKED — защита от replay-атак.
     *
     * @param rawRefreshToken refresh токен
     * @return новая пара токенов (access, refresh)
     */
    @Transactional
    public IssuedTokenPair rotateRefreshToken(String rawRefreshToken) {
        RefreshClaims claims = jwtVerifier.verify(rawRefreshToken, TokenKind.REFRESH)
                .claimsAs(RefreshClaims.class)
                .orElseThrow(() -> {
                    log.warn("Refresh rotation rejected: invalid JWT");
                    return new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
                });

        //поиск записи по token_hash в refresh tokens
        String tokenHash = hashToken(rawRefreshToken);
        RefreshTokens stored = refreshTokensRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Refresh rotation rejected: no stored record for provided token jti={}", claims.jti());
                    return new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
                });

        //Если токен старый/уже отозванный токен, это признак replay-атаки
        if (stored.getStatus() != Status.ACTIVE) {
            UUID familyId = stored.getTokenFamilyId();
            requiresNewTx.executeWithoutResult(tx -> refreshTokensRepository.revokeFamily(familyId));
            log.warn("Token replay detected — revoking entire family userId={} tokenFamilyId={} storedStatus={}",
                    stored.getUserId(), familyId, stored.getStatus());
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
        }

        //Проверка срока жизни записи в БД
        Instant now = Instant.now();
        if (stored.getExpiresAt().toInstant().isBefore(now)) {
            log.info("Refresh rotation rejected: expired userId={} expiresAt={}", stored.getUserId(), stored.getExpiresAt());
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        if (!blacklist.tryRevoke(claims.jti(), JwtTtl.secondsUntil(claims.expiresAt()))) {
            log.warn("Refresh rotation rejected: jti already blacklisted userId={} jti={}", stored.getUserId(), claims.jti());
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
        }

        UUID userId;
        try {
            userId = UUID.fromString(claims.userId());
        } catch (IllegalArgumentException e) {
            log.warn("Refresh rotation rejected: malformed userId in claims sub={}", claims.userId());
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Refresh rotation rejected: user not found userId={}", userId);
                    return new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
                });

        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Refresh rotation rejected: user not active userId={} status={}", userId, user.getStatus());
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        if (user.getLockedUntil() != null && now.isBefore(user.getLockedUntil())) {
            log.warn("Refresh rotation rejected: user locked userId={} until={}", userId, user.getLockedUntil());
            throw new BusinessException(
                    ErrorCode.ACCOUNT_TEMPORARILY_LOCKED,
                    "Вход временно заблокирован. Повторите через " + lockDurationMinutes + " мин.",
                    Map.of("retryAfterMinutes", lockDurationMinutes)
            );
        }

        stored.setStatus(Status.USED);
        refreshTokensRepository.save(stored);

        IssuedTokenPair pair = tokenPairIssuer.issue(user);
        persistRefreshToken(userId, stored.getTokenFamilyId(), pair);

        log.info("Refresh token rotated userId={} tokenFamilyId={}", userId, stored.getTokenFamilyId());
        return pair;
    }

    private void persistRefreshToken(UUID userId, UUID tokenFamilyId, IssuedTokenPair pair) {
        RefreshTokens entity = new RefreshTokens();
        entity.setUserId(userId);
        entity.setTokenFamilyId(tokenFamilyId);
        entity.setTokenHash(hashToken(pair.refreshToken()));
        entity.setStatus(Status.ACTIVE);
        entity.setExpiresAt(OffsetDateTime.ofInstant(
                Instant.now().plusSeconds(pair.refreshExpiresIn()), ZoneOffset.UTC));
        refreshTokensRepository.save(entity);
    }

    /**
     * Завершает сессию: оба jti попадают в blacklist, а вся семья refresh-токенов
     * (token_family_id) помечается REVOKED — чтобы даже при утечке blacklist'а
     * предъявленный refresh не прошёл проверку в rotateRefreshToken.
     *
     * @param rawAccessToken  access токен
     * @param rawRefreshToken refresh токен
     */
    @Transactional
    public void revokeAccessAndRefresh(String rawAccessToken, String rawRefreshToken) {
        revokeIfPresent(rawAccessToken, TokenKind.ACCESS);
        revokeIfPresent(rawRefreshToken, TokenKind.REFRESH);
        revokeRefreshFamilyIfPresent(rawRefreshToken);
    }

    private void revokeRefreshFamilyIfPresent(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        refreshTokensRepository.findByTokenHash(hashToken(rawRefreshToken))
                .ifPresent(r -> {
                    refreshTokensRepository.revokeFamily(r.getTokenFamilyId());
                    log.info("Logout: refresh token family revoked userId={} tokenFamilyId={}",
                            r.getUserId(), r.getTokenFamilyId());
                });
    }

    private void revokeIfPresent(String rawToken, TokenKind kind) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        jwtVerifier.verify(rawToken, kind).asClaims().ifPresent(c ->
                blacklist.revokeUntilExpiry(c.jti(), JwtTtl.secondsUntil(c.expiresAt()))
        );
    }

    private static String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
