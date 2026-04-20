package org.example.authmodule.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.authmodule.config.RefreshTokenCookieFactory;
import org.example.authmodule.dto.UserStatus;
import org.example.authmodule.dto.auth.request.LoginRequest;
import org.example.authmodule.dto.auth.request.RegisterRequest;
import org.example.authmodule.dto.auth.response.IssuedTokenPair;
import org.example.authmodule.dto.auth.response.UserResponse;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.example.authmodule.exception.GlobalExceptionHandler;
import org.example.authmodule.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthControllerTest {

    private final AuthService authService = mock(AuthService.class);
    private final RefreshTokenCookieFactory cookieFactory = mock(RefreshTokenCookieFactory.class);
    private final ObjectMapper mapper = new ObjectMapper();

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new AuthController(authService, cookieFactory))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void registerReturns201WithUserDto() throws Exception {
        RegisterRequest req = new RegisterRequest("u@example.com", "Password1!", "Full Name");
        UUID id = UUID.randomUUID();
        UserResponse dto = new UserResponse(id, "u@example.com", "Full Name", UserStatus.ACTIVE, Instant.parse("2026-01-01T00:00:00Z"));
        when(authService.register(any(RegisterRequest.class))).thenReturn(dto);

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.email").value("u@example.com"))
                .andExpect(jsonPath("$.data.fullName").value("Full Name"));
    }

    @Test
    void loginReturnsTokensAndSetCookie() throws Exception {
        LoginRequest req = new LoginRequest("u@example.com", "Password1!");
        IssuedTokenPair pair = new IssuedTokenPair("AT", "RT", 300, 86400, "Bearer");
        when(authService.login(any(LoginRequest.class))).thenReturn(pair);
        when(cookieFactory.create("RT")).thenReturn(ResponseCookie.from("refresh_token", "RT").path("/").build());

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("AT"))
                .andExpect(jsonPath("$.data.refreshToken").value("RT"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andExpect(cookie().value("refresh_token", "RT"));
    }

    @Test
    void loginReturns401WhenInvalidCredentials() throws Exception {
        LoginRequest req = new LoginRequest("u@example.com", "Password1!");
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new BusinessException(ErrorCode.INVALID_CREDENTIALS));

        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    void registerReturns400OnValidationError() throws Exception {
        RegisterRequest invalid = new RegisterRequest("not-an-email", "weak", "F");

        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(invalid)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void refreshReturns400WhenNoTokenProvided() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void refreshUsesBodyTokenAndReturnsNewPair() throws Exception {
        IssuedTokenPair pair = new IssuedTokenPair("AT2", "RT2", 300, 86400, "Bearer");
        when(authService.refresh("RT-old")).thenReturn(pair);
        when(cookieFactory.create("RT2")).thenReturn(ResponseCookie.from("refresh_token", "RT2").path("/").build());

        mvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"RT-old\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("AT2"))
                .andExpect(cookie().value("refresh_token", "RT2"));
    }

    @Test
    void logoutClearsCookieAndCallsService() throws Exception {
        when(cookieFactory.clear()).thenReturn(ResponseCookie.from("refresh_token", "").maxAge(0).path("/").build());

        mvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer AT-token"))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));

        verify(authService).logout("AT-token", null);
    }
}
