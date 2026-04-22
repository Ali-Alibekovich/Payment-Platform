package org.example.authmodule.service;

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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.*;

class SessionTokensServiceTest {

    private TokenPairIssuer issuer;
    private JwtVerifier verifier;
    private JtiBlacklistStore blacklist;
    private UserRepository userRepository;
    private RefreshTokensRepository refreshTokensRepository;
    private PlatformTransactionManager transactionManager;
    private SessionTokensService service;

    private static final long LOCK_MIN = 15;

    @BeforeEach
    void setUp() {
        issuer = mock(TokenPairIssuer.class);
        verifier = mock(JwtVerifier.class);
        blacklist = mock(JtiBlacklistStore.class);
        userRepository = mock(UserRepository.class);
        refreshTokensRepository = mock(RefreshTokensRepository.class);
        transactionManager = mock(PlatformTransactionManager.class);
        when(transactionManager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        service = new SessionTokensService(
                issuer,
                verifier,
                blacklist,
                userRepository,
                refreshTokensRepository,
                transactionManager,
                LOCK_MIN);
    }

    @Test
    void issuePairDelegatesToIssuerAndPersistsRefreshToken() {
        User user = activeUser();
        IssuedTokenPair pair = new IssuedTokenPair("at", "rt", 60, 120, "Bearer");
        when(issuer.issue(user)).thenReturn(pair);

        assertThat(service.issuePair(user)).isSameAs(pair);
        verify(refreshTokensRepository).save(any(RefreshTokens.class));
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
    void rotateThrowsInvalidWhenStoredRecordMissing() {
        UUID id = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateRevokesEntireFamilyWhenStoredRecordAlreadyUsed() {
        UUID id = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(id, familyId, Status.USED, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.REFRESH_TOKEN_REVOKED);

        verify(refreshTokensRepository).revokeFamily(familyId);
    }

    @Test
    void rotateThrowsInvalidWhenStoredRecordExpired() {
        UUID id = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(id, familyId, Status.ACTIVE, OffsetDateTime.now().minusMinutes(1));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateThrowsRevokedWhenBlacklisted() {
        UUID id = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(id, familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(false);

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.REFRESH_TOKEN_REVOKED);
    }

    @Test
    void rotateThrowsInvalidWhenUserIdNotUuid() {
        UUID familyId = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", "not-a-uuid", Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(UUID.randomUUID(), familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    void rotateThrowsInvalidWhenUserMissing() {
        UUID id = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(id, familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));
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
        UUID familyId = UUID.randomUUID();
        User user = activeUser();
        user.setUserId(id);
        user.setStatus(UserStatus.DISABLED);
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(id, familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));
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
        UUID familyId = UUID.randomUUID();
        User user = activeUser();
        user.setUserId(id);
        user.setLockedUntil(Instant.now().plusSeconds(60));
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), Instant.now().plusSeconds(60));
        RefreshTokens stored = storedToken(id, familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.rotateRefreshToken("rt"))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.ACCOUNT_TEMPORARILY_LOCKED);
    }

    @Test
    void rotateMarksStoredUsedAndIssuesNewPairWithSameFamily() {
        UUID id = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        User user = activeUser();
        user.setUserId(id);
        Instant exp = Instant.now().plusSeconds(120);
        RefreshClaims claims = new RefreshClaims("jti-1", id.toString(), exp);
        RefreshTokens stored = storedToken(id, familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(claims));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));
        when(blacklist.tryRevoke(eq("jti-1"), anyLong())).thenReturn(true);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        IssuedTokenPair pair = new IssuedTokenPair("at2", "rt2", 60, 120, "Bearer");
        when(issuer.issue(user)).thenReturn(pair);

        IssuedTokenPair result = service.rotateRefreshToken("rt");

        assertThat(result).isSameAs(pair);
        assertThat(stored.getStatus()).isEqualTo(Status.USED);
        verify(blacklist).tryRevoke(eq("jti-1"), anyLong());
        verify(refreshTokensRepository).save(stored);
        verify(refreshTokensRepository).save(argThat(rt ->
                rt != null
                        && familyId.equals(rt.getTokenFamilyId())
                        && id.equals(rt.getUserId())
                        && rt.getStatus() == Status.ACTIVE
                        && sha256("rt2").equals(rt.getTokenHash())
        ));
    }

    @Test
    void revokeIgnoresNullAndBlankTokens() {
        service.revokeAccessAndRefresh(null, "  ");

        verify(verifier, never()).verify(eq(null), eq(TokenKind.ACCESS));
        verify(blacklist, never()).revokeUntilExpiry(eq(null), anyLong());
        verify(refreshTokensRepository, never()).findByTokenHash(any());
    }

    @Test
    void revokeRevokesBothTokensAndFamily() {
        UUID familyId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        AccessClaims access = new AccessClaims("a-jti", "u@e.com", UUID.randomUUID().toString(), Set.of(), Instant.now().plusSeconds(60));
        RefreshClaims refresh = new RefreshClaims("r-jti", UUID.randomUUID().toString(), Instant.now().plusSeconds(120));
        RefreshTokens stored = storedToken(userId, familyId, Status.ACTIVE, OffsetDateTime.now().plusMinutes(5));
        when(verifier.verify("at", TokenKind.ACCESS)).thenReturn(new JwtParseResult.Ok(access));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Ok(refresh));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.of(stored));

        service.revokeAccessAndRefresh("at", "rt");

        verify(blacklist).revokeUntilExpiry(eq("a-jti"), anyLong());
        verify(blacklist).revokeUntilExpiry(eq("r-jti"), anyLong());
        verify(refreshTokensRepository).revokeFamily(familyId);
    }

    @Test
    void revokeSkipsTokenThatFailsVerification() {
        when(verifier.verify("at", TokenKind.ACCESS)).thenReturn(new JwtParseResult.Invalid("bad"));
        when(verifier.verify("rt", TokenKind.REFRESH)).thenReturn(new JwtParseResult.Invalid("bad"));
        when(refreshTokensRepository.findByTokenHash(sha256("rt"))).thenReturn(Optional.empty());

        service.revokeAccessAndRefresh("at", "rt");

        verify(blacklist, never()).revokeUntilExpiry(eq("a-jti"), anyLong());
        verify(blacklist, never()).revokeUntilExpiry(eq("r-jti"), anyLong());
        verify(refreshTokensRepository, never()).revokeFamily(any());
    }

    private static RefreshTokens storedToken(UUID userId, UUID familyId, Status status, OffsetDateTime expiresAt) {
        RefreshTokens t = new RefreshTokens();
        t.setId(UUID.randomUUID());
        t.setUserId(userId);
        t.setTokenFamilyId(familyId);
        t.setTokenHash("hash");
        t.setStatus(status);
        t.setExpiresAt(expiresAt);
        t.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return t;
    }

    private static String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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
