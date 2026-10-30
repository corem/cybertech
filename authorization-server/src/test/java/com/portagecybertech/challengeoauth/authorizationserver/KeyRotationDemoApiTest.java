package com.portagecybertech.challengeoauth.authorizationserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("demo")
class KeyRotationDemoApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void tokensAreSignedWithRotatedKey() throws Exception {
        String rotation = this.mockMvc.perform(post("/demo/keys/rotate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publishedKids.length()").value(2))
                .andReturn().getResponse().getContentAsString();

        String token = this.mockMvc
                .perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED).param("subject", "alice"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String kid = SignedJWT.parse(JsonPath.<String>read(token, "$.access_token")).getHeader().getKeyID();
        assertThat(kid).isEqualTo(JsonPath.<String>read(rotation, "$.activeKid"));
    }

}
