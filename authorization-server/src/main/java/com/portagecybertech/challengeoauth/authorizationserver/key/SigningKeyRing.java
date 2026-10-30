package com.portagecybertech.challengeoauth.authorizationserver.key;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Signing key ring. Extension point for plugging in a KMS or a vault without changing
 * token issuance or JWKS publication.
 */
public interface SigningKeyRing {

    /**
     * Key used to sign new tokens.
     */
    RSAKey activeKey();

    /**
     * All keys still in use, private parts included.
     */
    JWKSet signingKeys();

    /**
     * Public view of the key ring, the only form allowed to leave the service.
     */
    JWKSet publicKeys();

    /**
     * Activates a new key and keeps the previous one to verify tokens in circulation.
     */
    RSAKey rotate();

}
