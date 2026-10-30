package com.portagecybertech.challengeoauth.authorizationserver.token;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

@RestControllerAdvice(assignableTypes = TokenController.class)
class TokenExceptionHandler {

    private static final String INVALID_SUBJECT = "The 'subject' parameter is required and must contain between 1 and 255 characters";

    private static final String INVALID_PARAMETERS = "Parameters must be sent in the request body, each one only once";

    @ExceptionHandler({MissingServletRequestParameterException.class, HandlerMethodValidationException.class})
    ResponseEntity<TokenErrorResponse> handleInvalidSubject() {
        return invalidRequest(INVALID_SUBJECT);
    }

    @ExceptionHandler(InvalidTokenRequestException.class)
    ResponseEntity<TokenErrorResponse> handleInvalidParameters() {
        return invalidRequest(INVALID_PARAMETERS);
    }

    private static ResponseEntity<TokenErrorResponse> invalidRequest(String description) {
        return ResponseEntity.badRequest()
                .cacheControl(CacheControl.noStore())
                .body(new TokenErrorResponse("invalid_request", description));
    }

}
