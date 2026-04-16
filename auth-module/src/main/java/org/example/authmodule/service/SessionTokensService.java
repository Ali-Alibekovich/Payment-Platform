package org.example.authmodule.service;

import org.example.authmodule.dto.IssuedTokenPair;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.AccountLockedException;
import org.example.authmodule.exception.InvalidRefreshTokenException;
import org.example.authmodule.exception.RefreshTokenRevokedException;
import org.example.authmodule.jwt.*;
import org.example.authmodule.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
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

    public IssuedTokenPair issuePair(User user) {
        return tokenPairIssuer.issue(user);
    }

    @Transactional
    public IssuedTokenPair rotateRefreshToken(String rawRefreshToken) {
        RefreshClaims claims = jwtVerifier.verify(rawRefreshToken, TokenKind.REFRESH)
                .claimsAs(RefreshClaims.class)
                .orElseThrow(InvalidRefreshTokenException::new);

        if (blacklist.isRevoked(claims.jti())) {
            throw new RefreshTokenRevokedException();
        }

        UUID userId;
        try {
            userId = UUID.fromString(claims.userId());
        } catch (IllegalArgumentException e) {
            throw new InvalidRefreshTokenException();
        }

        User user = userRepository.findById(userId)
                .orElseThrow(InvalidRefreshTokenException::new);

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new InvalidRefreshTokenException();
        }

        Instant now = Instant.now();
        if (user.getLockedUntil() != null && now.isBefore(user.getLockedUntil())) {
            throw new AccountLockedException(lockDurationMinutes);
        }

        blacklist.revokeUntilExpiry(claims.jti(), JwtTtl.secondsUntil(claims.expiresAt()));

        return tokenPairIssuer.issue(user);
    }

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
