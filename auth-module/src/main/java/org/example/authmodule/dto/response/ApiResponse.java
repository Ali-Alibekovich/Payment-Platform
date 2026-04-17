package org.example.authmodule.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Класс обертка {"data": {...}}
 *
 * @param data - данные для обертки
 * @param <T>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(T data) {
    public static <T> ApiResponse<T> of(T data) {
        return new ApiResponse<>(data);
    }
}
