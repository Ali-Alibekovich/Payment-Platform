package org.example.authmodule.exception;

import org.example.authmodule.dto.error.ApiError;
import org.example.authmodule.dto.error.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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