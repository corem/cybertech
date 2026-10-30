package com.portagecybertech.challengeoauth.authorizationserver.key;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

class InMemorySigningKeyRingTest {

    private final InMemorySigningKeyRing keyRing = new InMemorySigningKeyRing();

    @Test
    void rotateActivatesNewKeyAndKeepsPreviousOne() {
        RSAKey previous = this.keyRing.activeKey();

        RSAKey rotated = this.keyRing.rotate();

        assertThat(this.keyRing.activeKey()).isEqualTo(rotated);
        assertThat(rotated.getKeyID()).isNotEqualTo(previous.getKeyID());
        assertThat(this.keyRing.publicKeys().getKeyByKeyId(previous.getKeyID())).isNotNull();
    }

    @Test
    void rotateRetainsAtMostTwoKeys() {
        RSAKey oldest = this.keyRing.activeKey();

        this.keyRing.rotate();
        this.keyRing.rotate();

        assertThat(this.keyRing.signingKeys().getKeys()).hasSize(2);
        assertThat(this.keyRing.signingKeys().getKeyByKeyId(oldest.getKeyID())).isNull();
    }

    @Test
    void publicKeysExposeNoPrivateMaterial() {
        this.keyRing.rotate();

        assertThat(this.keyRing.publicKeys().getKeys()).hasSize(2).noneMatch(JWK::isPrivate);
    }

}
