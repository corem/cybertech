package com.portagecybertech.challengeoauth.resourceserver.hello;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public HelloResponse hello(@AuthenticationPrincipal Jwt jwt) {
        return new HelloResponse("Hello, %s!".formatted(jwt.getSubject()));
    }

}
