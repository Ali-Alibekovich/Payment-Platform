package org.example.authmodule.exception;

import org.springframework.http.HttpStatus;

/**
 * Ошибки, их статус и описание
 */
public enum ErrorCode {

    EMAIL_ALREADY_EXISTS(
            HttpStatus.CONFLICT,
            "EMAIL_ALREADY_EXISTS",
            "Пользователь с таким email уже зарегистрирован"
    ),

    INVALID_CREDENTIALS(
            HttpStatus.UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "Неверный email или пароль"
    ),

    ACCOUNT_TEMPORARILY_LOCKED(
            HttpStatus.TOO_MANY_REQUESTS,
            "ACCOUNT_TEMPORARILY_LOCKED",
            "Вход временно заблокирован"
    ),

    INVALID_REFRESH_TOKEN(
            HttpStatus.UNAUTHORIZED,
            "INVALID_REFRESH_TOKEN",
            "Недействительный или просроченный refresh-токен"
    ),

    REFRESH_TOKEN_REVOKED(
            HttpStatus.UNAUTHORIZED,
            "REFRESH_TOKEN_REVOKED",
            "Сессия завершена. Выполните вход снова"
    ),

    VALIDATION_ERROR(
            HttpStatus.BAD_REQUEST,
            "VALIDATION_ERROR",
            "Проверьте введённые данные"
    ),

    REQUEST_FAILED(
            HttpStatus.BAD_REQUEST,
            "REQUEST_FAILED",
            "Ошибка запроса"
    );

    private final HttpStatus status;
    private final String code;
    private final String message;

    ErrorCode(HttpStatus status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }

    public String message() {
        return message;
    }
}