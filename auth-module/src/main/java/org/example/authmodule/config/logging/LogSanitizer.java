package org.example.authmodule.config.logging;

/**
 * Утилита для безопасного логирования PII — никогда не пишем сырые email/токены.
 */
public final class LogSanitizer {

    private LogSanitizer() {
    }

    /**
     * Маскирует локальную часть email: {@code user@gmail.com} → {@code u***r@gmail.com}.
     * Для логов достаточно, чтобы по email можно было соотнести события одного аккаунта,
     * но нельзя восстановить полный адрес.
     */
    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return "<empty>";
        }
        int at = email.indexOf('@');
        if (at < 1) {
            return "***";
        }
        String local = email.substring(0, at);
        String domain = email.substring(at);
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        return local.charAt(0) + "***" + local.charAt(local.length() - 1) + domain;
    }
}
