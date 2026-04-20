package org.example.authmodule.service;

import org.example.authcommon.security.JtiBlacklistStore;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.entity.User;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.jwt.*;
import org.example.authmodule.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class SessionTokensServiceTest {

    private TokenPairIssuer issuer;
    private JwtVerifier verifier;
    private JtiBlacklistStore blacklist;
    private UserRepository userRepository;
    private SessionTokensService service;

    private static final long LOCK_MIN = 15;

    @BeforeEach
    void setUp() {
        issuer = mock(TokenPairIssuer.class);
        verifier = mock(JwtVerifier.class);
        blacklist = mock(JtiBlacklistStore.class);
        userRepository = mock(UserRepository.class);
        service = new SessionTokensService(issuer, verifier, blacklist, userRepository, LOCK_MIN);
    }

    @Test
    void issuePairDelegatesToIssuer() {
        User user = activeUser();
        IssuedTokenPair pair = mock(IssuedTokenPair.class);
        when(issuer.issue(user)).thenReturn(pair);

        assertThat(service.issuePair(user)).isSameAs(pair);
    }

    @Test
    void rotateThrowsWhenVerifierReturnsInvalid() {
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Invalid("bad"));

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateThrowsRevokedWhenBlacklisted() {
        UUID id = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(false);

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.REFRESH_TOKEN_REVOKED);
    }

    @Test
    void rotateThrowsInvalidWhenUserIdNotUuid() {
        RefreshClaims claims = new RefreshClaims("jti-1", "not-a-uuid", Instant.now().plusSeconds(60));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateThrowsInvalidWhenUserMissing() {
        UUID id = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateThrowsInvalidWhenUserNotActive() {
        UUID id = UUID.randomUUID();
        User user = activeUser();
        user.setUserId(id);
        user.setStatus(UserStatus.DISABLED);
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateThrowsLockedWhenUserStillLocked() {
        UUID id = UUID.randomUUID();
        User user = activeUser();
        user.setUserId(id);
        user.setLockedUntil(Instant.now().plusSeconds(60));
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.ACCOUNT_TEMPORARILY_LOCKED);
    }

    @Test
    void rotateRevokesOldJtiAndIssuesNewPair() {
        UUID id = UUID.randomUUID();
        User user = activeUser();
        user.setUserId(id);
        Instant exp = Instant.now().plusSeconds(120);
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), exp);
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        IssuedTokenPair pair = mock(IssuedTokenPair.class);
        when(issuer.issue(user)).thenReturn(pair);

        IssuedTokenPair result = service.rotateRefreshToken("rt");

        assertThat(result).isSameAs(pair);
        verify(blacklist).tryRevoke(eq("jti-1"), anyLong());
    }

    @Test
    void revokeIgnoresNullAndBlankTokens() {
        service.revokeAccessAndRefresh(null, "  ");

        verify(verifier, never()).verify(eq(null), eq(TokenKind.ACCESS));
        verify(blacklist, never()).revokeUntilExpiry(eq(null), anyLong());
    }

    @Test
    void revokeRevokesBothTokens() {
        AccessClaims access = new AccessClaims("a-jti", "u@e.com", UUID.randomUUID().toString(), Set.of(), Instant.now().plusSeconds(60));
        RefreshClaims refresh = new RefreshClaims("r-jti", UUID.randomUUID().toString(), Instant.now().plusSeconds(120));
        when(verifier.verify("at", TokenKind.ACCESS)).thenReturn(new JwtParseResult.Ok(access));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(refresh));

        service.revokeAccessAndRefresh("at", "rt");

        verify(blacklist).revokeUntilExpiry(eq("a-jti"), anyLong());
        verify(blacklist).revokeUntilExpiry(eq("r-jti"), anyLong());
    }

    @Test
    void revokeSkipsTokenThatFailsVerification() {
        when(verifier.verify("at", TokenKind.ACCESS)).thenReturn(new JwtParseResult.Invalid("bad"));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Invalid("bad"));

        service.revokeAccessAndRefresh("at", "rt");

        verify(blacklist, never()).revokeUntilExpiry(eq("a-jti"), anyLong());
        verify(blacklist, never()).revokeUntilExpiry(eq("r-jti"), anyLong());
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
