package org.example.authmodule.dto.response;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public record ErrorResponse(ApiError error) {
    public static ResponseEntity<ErrorResponse> of(HttpStatus status,
                                                   String code,
                                                   String message) {
        return ResponseEntity.status(status)
                .body(new ErrorResponse(new ApiError(code, message, null)));
    }

    public static ResponseEntity<ErrorResponse> of(HttpStatus status,
                                                   String code,
                                                   String message,
                                                   Object details) {
        return ResponseEntity.status(status)
                .body(new ErrorResponse(new ApiError(code, message, details)));
    }
}