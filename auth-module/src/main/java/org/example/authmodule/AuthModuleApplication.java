package org.example.authmodule;

import org.example.authmodule.properties.AuthAdminProperties;
import org.example.authmodule.properties.AuthCookieProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({AuthCookieProperties.class, AuthAdminProperties.class})
public class AuthModuleApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthModuleApplication.class, args);
    }
}
