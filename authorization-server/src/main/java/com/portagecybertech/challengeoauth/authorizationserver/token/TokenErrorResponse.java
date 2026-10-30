package com.portagecybertech.challengeoauth.authorizationserver.token;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription) {
}
