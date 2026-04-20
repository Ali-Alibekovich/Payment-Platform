package org.example.authmodule.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Предоставляет {@link Clock} для инъекции в компоненты, которым нужно
 * знать текущее время (подпись/валидация JWT и т.п.). В тестах подменяется
 * на фиксированный/смещённый Clock, чтобы не зависеть от реального времени.
 */
@Configuration
public class TimeConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
