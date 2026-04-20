package org.example.authmodule.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.servlet.HandlerExceptionResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class DelegatingAuthenticationEntryPointTest {

    private final HandlerExceptionResolver resolver = mock(HandlerExceptionResolver.class);
    private final DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(resolver);

    @Test
    void delegatesBusinessExceptionWithInvalidAccessTokenCode() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        entryPoint.commence(req, resp, new BadCredentialsException("bad"));

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(resolver).resolveException(eq(req), eq(resp), isNull(), captor.capture());

        assertThat(captor.getValue()).isInstanceOf(BusinessException.class);
        BusinessException ex = (BusinessException) captor.getValue();
        assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_ACCESS_TOKEN);
    }
}
