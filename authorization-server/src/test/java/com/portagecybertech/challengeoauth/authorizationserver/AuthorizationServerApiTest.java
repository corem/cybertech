package com.portagecybertech.challengeoauth.authorizationserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationServerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void issuesTokenVerifiableWithPublishedKeys() throws Exception {
        String body = this.mockMvc
                .perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("subject", "alice"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andReturn().getResponse().getContentAsString();

        String jwks = this.mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/jwk-set+json"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        SignedJWT jwt = SignedJWT.parse(JsonPath.<String>read(body, "$.access_token"));
        var publicKey = JWKSet.parse(jwks).getKeyByKeyId(jwt.getHeader().getKeyID()).toRSAKey();
        assertThat(jwt.verify(new RSASSAVerifier(publicKey))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
    }

    @Test
    void rejectsMissingSubject() throws Exception {
        this.mockMvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void rejectsBlankSubject(String subject) throws Exception {
        this.mockMvc
                .perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("subject", subject))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsTooLongSubject() throws Exception {
        this.mockMvc
                .perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("subject", "a".repeat(256)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsRepeatedSubject() throws Exception {
        this.mockMvc
                .perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("subject", "alice", "admin"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void rejectsSubjectInBothQueryAndBody() throws Exception {
        this.mockMvc
                .perform(post("/oauth2/token?subject=admin").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("subject=alice"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsSubjectInQueryOnly() throws Exception {
        this.mockMvc.perform(post("/oauth2/token?subject=alice").contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void servesJwksToClientsAcceptingOnlyJson() throws Exception {
        this.mockMvc.perform(get("/.well-known/jwks.json").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.keys[0].kid").exists());
    }

    @Test
    void rotationEndpointDoesNotExistWithoutDemoProfile() throws Exception {
        this.mockMvc.perform(post("/demo/keys/rotate")).andExpect(status().isNotFound());
    }

    @Test
    void unknownRoutesAreDenied() throws Exception {
        this.mockMvc.perform(get("/anything")).andExpect(status().isForbidden());
    }

}
