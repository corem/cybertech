package com.portagecybertech.challengeoauth.authorizationserver.jwks;

import java.util.Map;

import com.portagecybertech.challengeoauth.authorizationserver.key.SigningKeyRing;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

    private final SigningKeyRing keyRing;

    public JwksController(SigningKeyRing keyRing) {
        this.keyRing = keyRing;
    }

    @GetMapping(path = "/.well-known/jwks.json", produces = {"application/jwk-set+json", MediaType.APPLICATION_JSON_VALUE})
    public Map<String, Object> jwks() {
        return this.keyRing.publicKeys().toJSONObject();
    }

}
