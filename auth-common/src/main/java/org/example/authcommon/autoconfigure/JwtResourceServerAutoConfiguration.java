package org.example.authcommon.autoconfigure;

import org.example.authcommon.jwt.JwtClaimNames;
import org.example.authcommon.jwt.JwtKeys;
import org.example.authcommon.jwt.JwtProperties;
import org.example.authcommon.security.AccessTokenTypeValidator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * Автоконфигурация resource-серверной части: собирает {@link JwtDecoder}
 * и {@link JwtAuthenticationConverter} из общих {@link JwtProperties}.
 *
 * <p>Дополнительные {@link OAuth2TokenValidator} (например,
 * {@link org.example.authcommon.security.JtiBlacklistValidator}) подхватываются
 * автоматически, если зарегистрированы как beans.
 *
 * <p>Все beans условные (@ConditionalOnMissingBean) — сервис может
 * переопределить любую часть, объявив свой bean.
 */
@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtResourceServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtKeys jwtKeys(JwtProperties properties) {
        return new JwtKeys(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(JwtKeys keys,
                                 ObjectProvider<OAuth2TokenValidator<Jwt>> extraValidators) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withSecretKey(keys.signingKey())
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(JwtValidators.createDefault());
        validators.add(new JwtIssuerValidator(keys.properties().issuer()));
        validators.add(new AccessTokenTypeValidator());
        extraValidators.orderedStream().forEach(validators::add);

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(JwtClaimNames.ROLES);
        authorities.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName(JwtClaimNames.USER_ID);
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }
}
