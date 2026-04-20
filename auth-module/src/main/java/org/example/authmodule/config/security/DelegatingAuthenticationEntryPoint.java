package org.example.authmodule.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.authmodule.exception.BusinessException;
import org.example.authmodule.exception.ErrorCode;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Превращает сбой аутентификации (bearer token отсутствует/битый/отозван/не того
 * типа) в {@link BusinessException} и пускает его через стандартный
 * {@link HandlerExceptionResolver}. Так клиент получает такой же
 * {@code ErrorResponse} 401, как и все остальные бизнес-ошибки.
 */
@Component
public class DelegatingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver resolver;

    public DelegatingAuthenticationEntryPoint(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver
    ) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) {
        resolver.resolveException(request, response, null,
                new BusinessException(ErrorCode.INVALID_ACCESS_TOKEN));
    }
}
