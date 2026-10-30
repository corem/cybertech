package com.portagecybertech.challengeoauth.authorizationserver.token;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import com.nimbusds.jose.jwk.RSAKey;
import com.portagecybertech.challengeoauth.authorizationserver.config.TokenProperties;
import com.portagecybertech.challengeoauth.authorizationserver.key.SigningKeyRing;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private static final String TOKEN_TYPE = "Bearer";

    private final JwtEncoder jwtEncoder;

    private final SigningKeyRing keyRing;

    private final TokenProperties properties;

    private final Clock clock;

    public TokenService(JwtEncoder jwtEncoder, SigningKeyRing keyRing, TokenProperties properties, Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.keyRing = keyRing;
        this.properties = properties;
        this.clock = clock;
    }

    public TokenResponse issueToken(String subject) {
        Instant now = this.clock.instant();
        RSAKey signingKey = this.keyRing.activeKey();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(signingKey.getKeyID()).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .id(UUID.randomUUID().toString())
                .issuer(this.properties.issuer())
                .subject(subject)
                .audience(this.properties.audience())
                .issuedAt(now)
                .expiresAt(now.plus(this.properties.timeToLive()))
                .build();
        String tokenValue = this.jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenResponse(tokenValue, TOKEN_TYPE, this.properties.timeToLive().toSeconds());
    }

}
