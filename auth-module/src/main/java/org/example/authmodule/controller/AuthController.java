package org.example.authmodule.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.authmodule.config.RefreshTokenCookieFactory;
import org.example.authmodule.dto.*;
import org.example.authmodule.dto.response.ApiResponse;
import org.example.authmodule.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenCookieFactory refreshTokenCookieFactory;

    @PostMapping(path = "/register")
    public ResponseEntity<ApiResponse<UserResponseDto>> register(@RequestBody @Valid RegisterRequest request) {
        UserResponseDto userResponseDto = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.of(userResponseDto));
    }

    @PostMapping(path = "/login")
    public ResponseEntity<ApiResponse<LoginResponseDto>> login(@RequestBody LoginRequest request) {
        var pair = authService.login(request);
        return ResponseEntity.status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieFactory.create(pair.refreshToken()).toString())
                .body(ApiResponse.of(pair.toBody()));
    }

    @PostMapping(path = "/refresh")
    public ResponseEntity<ApiResponse<LoginResponseDto>> refresh(
            @CookieValue(name = "${auth.cookies.refresh-token-name:refresh_token}", required = false) String refreshFromCookie,
            @RequestBody(required = false) RefreshTokenRequest body
    ) {
        String raw = firstNonBlank(refreshFromCookie, body != null ? body.refreshToken() : null);
        if (raw == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Нужен refresh-токен в cookie или в теле { \"refreshToken\": \"...\" }");
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
        String token = authHeader.replace("Bearer ", "");
        authService.logout(token, refreshToken);
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
