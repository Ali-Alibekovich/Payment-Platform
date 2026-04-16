package org.example.authmodule.exception;

import org.example.authmodule.dto.response.ApiError;
import org.example.authmodule.dto.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailExists(EmailAlreadyExistsException ex) {
        return ErrorResponse.of(HttpStatus.CONFLICT,
                "EMAIL_ALREADY_EXISTS",
                "Пользователь с таким email уже зарегистрирован");
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex) {
        if (ex.getRemainingAttempts() == null) {
            return ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                    "INVALID_CREDENTIALS",
                    "Неверный email или пароль");
        }
        int left = ex.getRemainingAttempts();
        return ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Неверный пароль. Осталось попыток: " + left,
                Map.of("remainingAttempts", left));
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ErrorResponse> handleAccountLocked(AccountLockedException ex) {
        long minutes = ex.getRetryAfterMinutes();
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(minutes * 60))
                .body(new ErrorResponse(new ApiError(
                        "ACCOUNT_TEMPORARILY_LOCKED",
                        "Вход заблокирован. Повторите через " + minutes + " мин.",
                        Map.of("retryAfterMinutes", minutes)
                )));
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefreshToken() {
        return ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                "INVALID_REFRESH_TOKEN",
                "Недействительный или просроченный refresh-токен");
    }

    @ExceptionHandler(RefreshTokenRevokedException.class)
    public ResponseEntity<ErrorResponse> handleRefreshRevoked() {
        return ErrorResponse.of(HttpStatus.UNAUTHORIZED,
                "REFRESH_TOKEN_REVOKED",
                "Сессия завершена. Выполните вход снова");
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ErrorResponse> handleResponseStatus(ResponseStatusException ex) {
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
        String message = ex.getReason() != null ? ex.getReason() : status.getReasonPhrase();
        return ErrorResponse.of(status, "REQUEST_FAILED", message);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        var fields = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> Map.of("field", e.getField(), "message", e.getDefaultMessage()))
                .toList();
        return ErrorResponse.of(HttpStatus.BAD_REQUEST,
                "VALIDATION_ERROR",
                "Проверьте введённые данные",
                Map.of("fields", fields));
    }
}