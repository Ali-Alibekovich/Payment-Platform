package org.example.authmodule;

import org.example.authmodule.properties.AuthCookieProperties;
import org.example.authmodule.properties.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({JwtProperties.class, AuthCookieProperties.class})
public class AuthModuleApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthModuleApplication.class, args);
    }
}
