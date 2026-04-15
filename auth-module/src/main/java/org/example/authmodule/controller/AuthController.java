package org.example.authmodule.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.authmodule.dto.*;
import org.example.authmodule.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping(path = "/register")
    public ResponseEntity<ApiResponse<UserResponseDto>> register(@RequestBody @Valid RegisterRequest request) {
        UserResponseDto userResponseDto = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.of(userResponseDto));
    }


    @PostMapping(path = "/login")
    public ResponseEntity<ApiResponse<LoginResponseDto>> login(@RequestBody LoginRequest request) {
        LoginResponseDto loginResponseDto = authService.login(request);
        return ResponseEntity.status(HttpStatus.OK).body(ApiResponse.of(loginResponseDto));
    }
}
