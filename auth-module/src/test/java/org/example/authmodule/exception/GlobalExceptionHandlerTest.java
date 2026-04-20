package org.example.authmodule.exception;

import org.example.authmodule.dto.error.ApiError;
import org.example.authmodule.dto.error.ErrorResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleBusinessReturnsErrorResponseFromCode() {
        BusinessException ex = new BusinessException(ErrorCode.EMAIL_ALREADY_EXISTS);

        ResponseEntity<ErrorResponse> response = handler.handleBusiness(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        ApiError err = Objects.requireNonNull(response.getBody()).error();
        assertThat(err.code()).isEqualTo("EMAIL_ALREADY_EXISTS");
        assertThat(err.message()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS.message());
        assertThat(err.details()).isNull();
    }

    @Test
    void handleBusinessIncludesDetailsAndCustomMessage() {
        BusinessException ex = new BusinessException(
                ErrorCode.INVALID_CREDENTIALS,
                "Custom message",
                Map.of("remainingAttempts", 2)
        );

        ResponseEntity<ErrorResponse> response = handler.handleBusiness(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        ApiError err = Objects.requireNonNull(response.getBody()).error();
        assertThat(err.message()).isEqualTo("Custom message");
        assertThat(err.details()).containsEntry("remainingAttempts", 2);
    }

    @Test
    void handleValidationCollectsFieldErrors() {
        FieldError fe1 = new FieldError("req", "email", "must not be blank");
        FieldError fe2 = new FieldError("req", "password", "too short");
        BindingResult br = mock(BindingResult.class);
        when(br.getFieldErrors()).thenReturn(List.of(fe1, fe2));
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        when(ex.getBindingResult()).thenReturn(br);

        ResponseEntity<ErrorResponse> response = handler.handleValidation(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        ApiError err = Objects.requireNonNull(response.getBody()).error();
        assertThat(err.code()).isEqualTo("VALIDATION_ERROR");
        @SuppressWarnings("unchecked")
        List<Map<String, String>> fields = (List<Map<String, String>>) err.details().get("fields");
        assertThat(fields).hasSize(2);
        assertThat(fields.get(0)).containsEntry("field", "email").containsEntry("message", "must not be blank");
        assertThat(fields.get(1)).containsEntry("field", "password").containsEntry("message", "too short");
    }
}
