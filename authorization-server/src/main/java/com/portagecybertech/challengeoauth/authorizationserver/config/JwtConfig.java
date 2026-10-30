package com.portagecybertech.challengeoauth.authorizationserver.config;

import java.time.Clock;

import com.portagecybertech.challengeoauth.authorizationserver.key.SigningKeyRing;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration(proxyBeanMethods = false)
public class JwtConfig {

    @Bean
    JwtEncoder jwtEncoder(SigningKeyRing keyRing) {
        return new NimbusJwtEncoder((selector, context) -> selector.select(keyRing.signingKeys()));
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

}
