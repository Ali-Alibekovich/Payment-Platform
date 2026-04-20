package org.example.authmodule.dto.error;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * Класс для описания ошибок
 *
 * @param code    код ошибки
 * @param message сообщение ошибки
 * @param details детали
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(String code, String message, Map<String, Object> details) {
}
