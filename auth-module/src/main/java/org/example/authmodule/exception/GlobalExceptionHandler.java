package org.example.authmodule.exception;

import org.example.authmodule.dto.response.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.Objects;

/**
 * Обработка ошибок приложения
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorResponse> handleBusiness(BusinessException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        return ErrorResponse.of(
                errorCode.status(),
                errorCode.code(),
                ex.getMessage(),
                ex.getDetails()
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        var fields = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> Map.of(
                        "field", error.getField(),
                        "message", Objects.requireNonNull(error.getDefaultMessage())
                ))
                .toList();

        return ErrorResponse.of(
                ErrorCode.VALIDATION_ERROR.status(),
                ErrorCode.VALIDATION_ERROR.code(),
                ErrorCode.VALIDATION_ERROR.message(),
                Map.of("fields", fields)
        );
    }
}