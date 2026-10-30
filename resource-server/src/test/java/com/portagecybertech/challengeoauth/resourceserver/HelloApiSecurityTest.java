package com.portagecybertech.challengeoauth.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
class HelloApiSecurityTest {

    private static final String ISSUER = "http://issuer.test";

    private static final String AUDIENCE = "hello-api";

    private static final String RESOURCE_URL = "http://hello.test";

    private static final StubJwksServer JWKS = new StubJwksServer();

    private static final RSAKey CURRENT_KEY = generateKey();

    @Autowired
    private MockMvc mockMvc;

    @DynamicPropertySource
    static void securityProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", JWKS::url);
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> ISSUER);
        registry.add("spring.security.oauth2.resourceserver.jwt.audiences", () -> AUDIENCE);
        registry.add("resource-server.url", () -> RESOURCE_URL);
    }

    @BeforeEach
    void publishCurrentKey() {
        JWKS.publish(CURRENT_KEY);
    }

    @Test
    void acceptsValidTokenAndGreetsSubject() throws Exception {
        callHello(sign(CURRENT_KEY, validClaims().build()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello, alice!"));
    }

    @Test
    void rejectsMissingToken() throws Exception {
        this.mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")));
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        // Beyond the 60-second clock tolerance applied by Spring Security
        Instant now = Instant.now();
        assertRejected(sign(CURRENT_KEY, validClaims().issueTime(Date.from(now.minus(Duration.ofMinutes(10))))
                .expirationTime(Date.from(now.minus(Duration.ofMinutes(2))))
                .build()));
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        assertRejected(sign(CURRENT_KEY, validClaims().issuer("http://evil.test").build()));
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        assertRejected(sign(CURRENT_KEY, validClaims().audience("other-api").build()));
    }

    @Test
    void rejectsTokenSignedWithUnpublishedKey() throws Exception {
        assertRejected(sign(generateKey(), validClaims().build()));
    }

    @Test
    void rejectsTokenWhoseClaimsWereTampered() throws Exception {
        String[] genuine = sign(CURRENT_KEY, validClaims().build()).split("\\.");
        String[] forged = sign(CURRENT_KEY, validClaims().subject("admin").build()).split("\\.");
        assertRejected(genuine[0] + "." + forged[1] + "." + genuine[2]);
    }

    @Test
    void rejectsUnsignedToken() throws Exception {
        assertRejected(new PlainJWT(validClaims().build()).serialize());
    }

    @Test
    void rejectsHmacTokenEvenWithKidOfPublishedKey() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(CURRENT_KEY.getKeyID()).build(),
                validClaims().build());
        jwt.sign(new MACSigner(CURRENT_KEY.toPublicJWK().getModulus().decode()));
        assertRejected(jwt.serialize());
    }

    @Test
    void rejectsTokenWithoutExpiration() throws Exception {
        assertRejected(sign(CURRENT_KEY, validClaims().expirationTime(null).build()));
    }

    @Test
    void rejectsTokenWithoutSubject() throws Exception {
        assertRejected(sign(CURRENT_KEY, validClaims().subject(null).build()));
    }

    @Test
    void rejectsTokenWithoutIssuedAt() throws Exception {
        assertRejected(sign(CURRENT_KEY, validClaims().issueTime(null).build()));
    }

    @Test
    void rejectsTokenIssuedInTheFuture() throws Exception {
        Instant now = Instant.now();
        assertRejected(sign(CURRENT_KEY, validClaims().issueTime(Date.from(now.plus(Duration.ofHours(1))))
                .expirationTime(Date.from(now.plus(Duration.ofHours(2))))
                .build()));
    }

    @Test
    void toleratesClockSkewOnIssuedAt() throws Exception {
        Instant now = Instant.now();
        callHello(sign(CURRENT_KEY, validClaims().issueTime(Date.from(now.plus(Duration.ofSeconds(30)))).build()))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsTokenWithExcessiveLifetime() throws Exception {
        Instant now = Instant.now();
        assertRejected(sign(CURRENT_KEY, validClaims().expirationTime(Date.from(now.plus(Duration.ofHours(25)))).build()));
    }

    @Test
    void acceptsTokenListingSeveralAudiences() throws Exception {
        callHello(sign(CURRENT_KEY, validClaims().audience(List.of("other-api", AUDIENCE)).build()))
                .andExpect(status().isOk());
    }

    @Test
    void challengeIgnoresHostHeader() throws Exception {
        this.mockMvc.perform(get("http://evil.test/api/hello"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate",
                        containsString("resource_metadata=\"" + RESOURCE_URL + "/.well-known/oauth-protected-resource\"")))
                .andExpect(header().string("WWW-Authenticate", not(containsString("evil.test"))));
    }

    @Test
    void metadataIgnoresHostHeaderAndDescribesThisServer() throws Exception {
        this.mockMvc.perform(get("http://evil.test/.well-known/oauth-protected-resource"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resource").value(RESOURCE_URL))
                .andExpect(jsonPath("$.authorization_servers[0]").value(ISSUER))
                .andExpect(jsonPath("$.tls_client_certificate_bound_access_tokens").value(false));
    }

    @Test
    void acceptsTokenSignedWithRotatedKeyWithoutRestart() throws Exception {
        callHello(sign(CURRENT_KEY, validClaims().build())).andExpect(status().isOk());

        RSAKey rotatedKey = generateKey();
        JWKS.publish(rotatedKey, CURRENT_KEY);

        callHello(sign(rotatedKey, validClaims().build())).andExpect(status().isOk());
        callHello(sign(CURRENT_KEY, validClaims().build())).andExpect(status().isOk());
    }

    @Test
    void knownKeysAreServedFromCache() throws Exception {
        callHello(sign(CURRENT_KEY, validClaims().build())).andExpect(status().isOk());
        int fetchesAfterWarmUp = JWKS.fetchCount();

        callHello(sign(CURRENT_KEY, validClaims().build())).andExpect(status().isOk());

        assertThat(JWKS.fetchCount()).isEqualTo(fetchesAfterWarmUp);
    }

    private ResultActions callHello(String token) throws Exception {
        return this.mockMvc.perform(get("/api/hello").header("Authorization", "Bearer " + token));
    }

    private void assertRejected(String token) throws Exception {
        callHello(token).andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")));
    }

    private static JWTClaimsSet.Builder validClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString())
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject("alice")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))));
    }

    private static String sign(RSAKey key, JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        } catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }

}
