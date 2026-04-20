package org.example.authmodule.dto.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

/**
 * Класс для формирования ответа с ошибкой
 *
 * @param error
 */
public record ErrorResponse(ApiError error) {

    public static ResponseEntity<ErrorResponse> of(HttpStatus status,
                                                   String code,
                                                   String message,
                                                   Map<String, Object> details) {
        return ResponseEntity.status(status)
                .body(new ErrorResponse(new ApiError(code, message, details)));
    }
}