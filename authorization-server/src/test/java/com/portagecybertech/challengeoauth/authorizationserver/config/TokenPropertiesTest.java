package com.portagecybertech.challengeoauth.authorizationserver.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

class TokenPropertiesTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfiguration.class)
            .withPropertyValues("token.issuer=http://localhost:9000", "token.audience=hello-api", "token.time-to-live=15m");

    @Test
    void acceptsValidConfiguration() {
        this.contextRunner.run((context) -> {
            TokenProperties properties = context.getBean(TokenProperties.class);
            assertThat(properties.timeToLive()).isEqualTo(Duration.ofMinutes(15));
            assertThat(properties.audience()).containsExactly("hello-api");
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1m", "0s", "500ms", "25h"})
    void refusesToStartWithTimeToLiveOutOfRange(String timeToLive) {
        this.contextRunner.withPropertyValues("token.time-to-live=" + timeToLive)
                .run((context) -> assertThat(context).hasFailed());
    }

    @ParameterizedTest
    @ValueSource(strings = {"1s", "24h"})
    void acceptsTimeToLiveBounds(String timeToLive) {
        this.contextRunner.withPropertyValues("token.time-to-live=" + timeToLive)
                .run((context) -> assertThat(context).hasNotFailed());
    }

    @Test
    void refusesToStartWithIssuerThatIsNotAUrl() {
        this.contextRunner.withPropertyValues("token.issuer=not a url")
                .run((context) -> assertThat(context).hasFailed());
    }

    @Test
    void splitsCommaSeparatedAudiences() {
        this.contextRunner.withPropertyValues("token.audience=api-a,api-b")
                .run((context) -> assertThat(context.getBean(TokenProperties.class).audience())
                        .containsExactly("api-a", "api-b"));
    }

    @Test
    void refusesToStartWithoutAudience() {
        this.contextRunner.withPropertyValues("token.audience=")
                .run((context) -> assertThat(context).hasFailed());
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(TokenProperties.class)
    static class PropertiesConfiguration {

    }

}
