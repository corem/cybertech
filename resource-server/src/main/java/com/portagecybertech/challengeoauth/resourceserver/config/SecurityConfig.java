package com.portagecybertech.challengeoauth.resourceserver.config;

import java.time.Clock;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The JWT decoder (keys via JWKS, validation of the signature, "iss", "aud" and "exp") is
 * auto-configured by Spring Boot from application.properties.
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    private static final String METADATA_PATH = "/.well-known/oauth-protected-resource";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, @Value("${resource-server.url}") String resourceUrl,
                                            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer) {
        BearerTokenAuthenticationEntryPoint entryPoint = new BearerTokenAuthenticationEntryPoint();
        entryPoint.setResourceMetadataParameterResolver(request -> resourceUrl + METADATA_PATH);
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(entryPoint)
                        .protectedResourceMetadata(metadata -> metadata.protectedResourceMetadataCustomizer(builder -> builder
                                .resource(resourceUrl)
                                .authorizationServer(issuer)
                                .tlsClientCertificateBoundAccessTokens(false))))
                .build();
    }

    @Bean
    OAuth2TokenValidator<Jwt> tokenClaimsValidator() {
        return new TokenClaimsValidator(Clock.systemUTC());
    }

}
