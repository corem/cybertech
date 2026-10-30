package com.portagecybertech.challengeoauth.authorizationserver.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.portagecybertech.challengeoauth.authorizationserver.config.TokenProperties;
import com.portagecybertech.challengeoauth.authorizationserver.key.InMemorySigningKeyRing;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

class TokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    private final InMemorySigningKeyRing keyRing = new InMemorySigningKeyRing();

    private final TokenService tokenService = new TokenService(
            new NimbusJwtEncoder((selector, context) -> selector.select(this.keyRing.signingKeys())), this.keyRing,
            new TokenProperties("http://issuer.test", List.of("hello-api"), Duration.ofMinutes(15)),
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void issuedTokenCarriesExpectedClaims() throws ParseException {
        TokenResponse response = this.tokenService.issueToken("alice");

        JWTClaimsSet claims = SignedJWT.parse(response.accessToken()).getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getIssuer()).isEqualTo("http://issuer.test");
        assertThat(claims.getAudience()).isEqualTo(List.of("hello-api"));
        assertThat(claims.getIssueTime()).isEqualTo(Date.from(NOW));
        assertThat(claims.getExpirationTime()).isEqualTo(Date.from(NOW.plus(Duration.ofMinutes(15))));
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
    }

    @Test
    void tokenListsEachConfiguredAudience() throws ParseException {
        TokenService service = new TokenService(
                new NimbusJwtEncoder((selector, context) -> selector.select(this.keyRing.signingKeys())), this.keyRing,
                new TokenProperties("http://issuer.test", List.of("api-a", "api-b"), Duration.ofMinutes(15)),
                Clock.fixed(NOW, ZoneOffset.UTC));

        JWTClaimsSet claims = SignedJWT.parse(service.issueToken("alice").accessToken()).getJWTClaimsSet();

        assertThat(claims.getAudience()).containsExactly("api-a", "api-b");
    }

    @Test
    void tokenIsSignedWithActiveKeyAndIdentifiesIt() throws ParseException, JOSEException {
        this.keyRing.rotate();

        SignedJWT jwt = SignedJWT.parse(this.tokenService.issueToken("alice").accessToken());

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(this.keyRing.activeKey().getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(this.keyRing.activeKey().toPublicJWK()))).isTrue();
    }

}
