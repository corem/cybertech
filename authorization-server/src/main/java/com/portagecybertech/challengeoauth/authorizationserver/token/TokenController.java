package com.portagecybertech.challengeoauth.authorizationserver.token;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping(path = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<TokenResponse> issueToken(@RequestParam @NotBlank @Size(max = 255) String subject,
                                                    HttpServletRequest request) {
        if (request.getQueryString() != null || request.getParameterValues("subject").length > 1) {
            throw new InvalidTokenRequestException();
        }
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(this.tokenService.issueToken(subject));
    }

}
