package org.example.authcommon.jwt;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * Вывод симметричного ключа подписи HS256 из {@code jwt.secret}. Используется
 * и эмитентом (для подписи), и resource-серверами (для верификации) — тот же
 * алгоритм гарантирует одинаковый ключ из одинакового секрета.
 *
 * <p>Применяется HKDF-SHA256 (RFC 5869). {@code info} привязывает материал
 * к назначению и issuer — смена issuer даёт независимый ключ из того же
 * секрета (domain separation).
 */
public class JwtKeys {

    private static final String HMAC_ALG = "HmacSHA256";
    private static final int HASH_LEN = 32;
    private static final int MIN_SECRET_BYTES = 32;
    private static final String KEY_INFO_PREFIX = "payment-platform-auth:jwt-hs256:v1:";

    private final JwtProperties properties;
    private final SecretKey signingKey;

    public JwtKeys(JwtProperties properties) {
        if (properties.secret() == null || properties.secret().isBlank()) {
            throw new IllegalStateException(
                    "jwt.secret must be set (e.g. JWT_SECRET env in production)");
        }
        byte[] ikm = properties.secret().getBytes(StandardCharsets.UTF_8);
        if (ikm.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "jwt.secret must be at least " + MIN_SECRET_BYTES + " bytes (UTF-8) of entropy");
        }
        this.properties = properties;
        this.signingKey = deriveKey(ikm, properties.issuer());
    }

    public JwtProperties properties() {
        return properties;
    }

    public SecretKey signingKey() {
        return signingKey;
    }

    private static SecretKey deriveKey(byte[] ikm, String issuer) {
        byte[] salt = new byte[HASH_LEN];
        byte[] info = (KEY_INFO_PREFIX + issuer).getBytes(StandardCharsets.UTF_8);
        byte[] prk = hmacSha256(salt, ikm);

        byte[] expandInput = new byte[info.length + 1];
        System.arraycopy(info, 0, expandInput, 0, info.length);
        expandInput[info.length] = 0x01;
        byte[] okm = hmacSha256(prk, expandInput);

        return new SecretKeySpec(okm, HMAC_ALG);
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(key, HMAC_ALG));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(HMAC_ALG + " unavailable", e);
        }
    }
}
