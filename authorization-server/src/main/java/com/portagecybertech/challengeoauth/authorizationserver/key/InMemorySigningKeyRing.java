package com.portagecybertech.challengeoauth.authorizationserver.key;

import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import org.springframework.stereotype.Component;

/**
 * Keys are generated at startup and kept in memory: a restart therefore invalidates issued
 * tokens, and this key ring is not suitable for multiple instances.
 */
@Component
public class InMemorySigningKeyRing implements SigningKeyRing {

    private static final int KEY_SIZE_BITS = 2048;

    /**
     * Immutable list, active key first: reads take no lock.
     */
    private volatile List<RSAKey> keys = List.of(generateKey());

    @Override
    public RSAKey activeKey() {
        return this.keys.getFirst();
    }

    @Override
    public JWKSet signingKeys() {
        return new JWKSet(List.copyOf(this.keys));
    }

    @Override
    public JWKSet publicKeys() {
        return signingKeys().toPublicJWKSet();
    }

    @Override
    public synchronized RSAKey rotate() {
        RSAKey newKey = generateKey();
        this.keys = List.of(newKey, this.keys.getFirst());
        return newKey;
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(KEY_SIZE_BITS)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .generate();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Unable to generate the signing key", ex);
        }
    }

}
