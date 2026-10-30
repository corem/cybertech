package com.portagecybertech.challengeoauth.authorizationserver.config;

import java.time.Duration;
import java.util.List;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("token")
public record TokenProperties(@NotBlank @URL String issuer, @NotEmpty List<@NotBlank String> audience,
                              @NotNull Duration timeToLive) {

    private static final Duration MIN_TIME_TO_LIVE = Duration.ofSeconds(1);

    private static final Duration MAX_TIME_TO_LIVE = Duration.ofHours(24);

    @AssertTrue(message = "must be between 1 second and 24 hours")
    public boolean isTimeToLiveInRange() {
        return this.timeToLive == null || (this.timeToLive.compareTo(MIN_TIME_TO_LIVE) >= 0
                && this.timeToLive.compareTo(MAX_TIME_TO_LIVE) <= 0);
    }

}
