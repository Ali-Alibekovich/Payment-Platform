package org.example.authmodule.exception;

import lombok.Getter;

/**
 * Вход заблокирован после превышения числа неверных попыток.
 */
@Getter
public class AccountLockedException extends RuntimeException {

    private final long retryAfterMinutes;

    public AccountLockedException(long retryAfterMinutes) {
        this.retryAfterMinutes = retryAfterMinutes;
    }
}
