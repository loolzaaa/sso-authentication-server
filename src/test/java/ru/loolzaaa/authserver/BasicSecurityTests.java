package ru.loolzaaa.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import ru.loolzaaa.authserver.config.security.property.BasicUsersProperties;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestProfiles
@SpringBootTest
class BasicSecurityTests {

    @Autowired
    WebApplicationContext context;

    @Autowired
    BasicUsersProperties basicUsersProperties;

    @Autowired
    SsoServerProperties ssoServerProperties;

    BasicUsersProperties.BasicUser user;

    MockMvc mvc;

    @BeforeEach
    public void setup() {
        user = basicUsersProperties.getUsers().get(0);

        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void shouldReturn200ForGetUser() throws Exception {
        mvc
                .perform(get("/api/fast/user/admin")
                        .with(httpBasic(user.getUsername(), user.getPassword())))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturn200ForGetUsers() throws Exception {
        mvc
                .perform(get("/api/fast/users")
                        .queryParam("app", ssoServerProperties.getApplication().getName())
                        .queryParam("authority", ssoServerProperties.getApplication().getName())
                        .with(httpBasic(user.getUsername(), user.getPassword())))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturn400ForUpdateConfig() throws Exception {
        mvc
                .perform(patch("/api/fast/user/dummy/config/dummy")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(httpBasic(user.getUsername(), user.getPassword())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldReturn403ForRevokeToken() throws Exception {
        mvc
                .perform(post("/api/fast/prepare_logout")
                        .header("Revoke-Token", "TOKEN")
                        .with(httpBasic(user.getUsername(), user.getPassword())))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldReturn204ForRevokeToken() throws Exception {
        mvc
                .perform(post("/api/fast/prepare_logout")
                        .header("Revoke-Token", "TOKEN")
                        .with(httpBasic(basicUsersProperties.getRevokeUsername(), basicUsersProperties.getRevokePassword())))
                .andExpect(status().isNoContent());
    }
}
