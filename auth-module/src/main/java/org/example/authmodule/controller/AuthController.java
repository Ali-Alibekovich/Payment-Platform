package org.example.authmodule.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.authmodule.config.RefreshTokenCookieFactory;
import org.example.authmodule.dto.ApiResponse;
import org.example.authmodule.dto.auth.request.LoginRequest;
import org.example.authmodule.dto.auth.request.RefreshTokenRequest;
import org.example.authmodule.dto.auth.request.RegisterRequest;
import org.example.authmodule.dto.auth.response.LoginResponse;
import org.example.authmodule.dto.auth.response.UserResponse;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


/**
 * Контроллер авторизации
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenCookieFactory refreshTokenCookieFactory;

    @PostMapping(path = "/register")
    public ResponseEntity<ApiResponse<UserResponse>> register(@RequestBody @Valid RegisterRequest request) {
        UserResponse userResponse = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.of(userResponse));
    }

    @PostMapping(path = "/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody @Valid LoginRequest request) {
        var pair = authService.login(request);
        return ResponseEntity.status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieFactory.create(pair.refreshToken()).toString())
                .body(ApiResponse.of(pair.toBody()));
    }

    @PostMapping(path = "/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refresh(
            @CookieValue(name = "${auth.cookies.refresh-token-name:refresh_token}", required = false) String refreshFromCookie,
            @RequestBody(required = false) RefreshTokenRequest body
    ) {
        String raw = firstNonBlank(refreshFromCookie, body != null ? body.refreshToken() : null);
        if (raw == null) {
            throw new BusinessException(
                    ErrorCode.VALIDATION_ERROR,
                    "Проверьте введённые данные",
                    Map.of("fields", List.of(Map.of(
                            "field", "refreshToken",
                            "message", "Нужен refresh-токен в cookie или в теле запроса"
                    )))
            );
        }
        var pair = authService.refresh(raw);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieFactory.create(pair.refreshToken()).toString())
                .body(ApiResponse.of(pair.toBody()));
    }

    @PostMapping(path = "/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String authHeader,
            @CookieValue(name = "${auth.cookies.refresh-token-name:refresh_token}", required = false) String refreshToken
    ) {
        String rawToken = authHeader.startsWith("Bearer") ? authHeader.substring(7) : null;
        authService.logout(rawToken, refreshToken);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieFactory.clear().toString())
                .build();
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        if (b != null && !b.isBlank()) {
            return b;
        }
        return null;
    }
}
