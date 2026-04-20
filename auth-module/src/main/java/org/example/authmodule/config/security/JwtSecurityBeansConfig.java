package org.example.authmodule.config.security;

import org.example.authcommon.security.JtiBlacklistStore;
import org.example.authcommon.security.JtiBlacklistValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Регистрирует бины из auth-common, специфичные для auth-module:
 * <ul>
 *   <li>{@link JtiBlacklistStore} — хранилище отозванных jti в Redis;</li>
 *   <li>{@link JtiBlacklistValidator} — валидатор токенов, подхватываемый
 *       {@code JwtResourceServerAutoConfiguration} через {@code ObjectProvider}.</li>
 * </ul>
 */
@Configuration
public class JwtSecurityBeansConfig {

    @Bean
    public JtiBlacklistStore jtiBlacklistStore(RedisTemplate<String, Object> redisTemplate) {
        return new JtiBlacklistStore(redisTemplate);
    }

    @Bean
    public JtiBlacklistValidator jtiBlacklistValidator(JtiBlacklistStore blacklist) {
        return new JtiBlacklistValidator(blacklist);
    }
}
