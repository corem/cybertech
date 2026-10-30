package com.portagecybertech.challengeoauth.resourceserver.config;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * Complements the Spring Security validators, which ignore missing claims: a token without
 * "exp" would otherwise stay valid forever.
 */
final class TokenClaimsValidator implements OAuth2TokenValidator<Jwt> {

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    private static final Duration MAX_LIFETIME = Duration.ofHours(24);

    private final Clock clock;

    TokenClaimsValidator(Clock clock) {
        this.clock = clock;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (!StringUtils.hasText(jwt.getSubject())) {
            return invalid("The sub claim is required");
        }
        Instant issuedAt = jwt.getIssuedAt();
        Instant expiresAt = jwt.getExpiresAt();
        if (issuedAt == null || expiresAt == null) {
            return invalid("The iat and exp claims are required");
        }
        if (issuedAt.isAfter(this.clock.instant().plus(CLOCK_SKEW))) {
            return invalid("The iat claim cannot be in the future");
        }
        if (Duration.between(issuedAt, expiresAt).compareTo(MAX_LIFETIME) > 0) {
            return invalid("The token lifetime exceeds the allowed maximum");
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult invalid(String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, null));
    }

}
