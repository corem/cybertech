package com.portagecybertech.challengeoauth.authorizationserver.demo;

import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.portagecybertech.challengeoauth.authorizationserver.key.SigningKeyRing;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Simulates a key rotation for the demo. Unauthenticated: it only exists with the "demo"
 * profile and must never be enabled outside a local workstation.
 */
@Profile("demo")
@RestController
public class KeyRotationController {

    private final SigningKeyRing keyRing;

    public KeyRotationController(SigningKeyRing keyRing) {
        this.keyRing = keyRing;
    }

    @PostMapping("/demo/keys/rotate")
    public KeyRotationResponse rotate() {
        String activeKid = this.keyRing.rotate().getKeyID();
        List<String> publishedKids = this.keyRing.publicKeys().getKeys().stream().map(JWK::getKeyID).toList();
        return new KeyRotationResponse(activeKid, publishedKids);
    }

}
