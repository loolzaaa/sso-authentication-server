package ru.loolzaaa.authserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.WithMockJwtUser;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.dto.CreateUserRequestDTO;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@TestProfiles
@SpringBootTest
class JwtSecurityTests {

    @Autowired
    WebApplicationContext context;

    @Autowired
    ObjectMapper mapper;

    @Autowired
    SsoServerProperties ssoServerProperties;

    MockMvc mvc;

    @BeforeEach
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    void shouldRedirectAndCookieTokenReturnAfterLogin() throws Exception {
        mvc
                .perform(post("/do_login")
                        .param("username", "admin")
                        .param("password", "pass")
                        .param("_fingerprint", "TEST")
                        .param("_authenticationMode", "sso")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(cookie().exists(CookieName.ACCESS.getName()))
                .andExpect(cookie().exists(CookieName.REFRESH.getName()));
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn200ForMainPage() throws Exception {
        mvc
                .perform(get("/")
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn200ForGetUser() throws Exception {
        mvc
                .perform(get("/api/user/admin")
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn200ForGetUsers() throws Exception {
        mvc
                .perform(get("/api/user/admin")
                        .queryParam("app", ssoServerProperties.getApplication().getName())
                        .queryParam("authority", ssoServerProperties.getApplication().getName())
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn403ForCreateUser() throws Exception {
        CreateUserRequestDTO dto = new CreateUserRequestDTO();
        dto.setLogin("");
        dto.setName("");
        dto.setConfig(mapper.createObjectNode());

        mvc
                .perform(put("/api/user?app=" + ssoServerProperties.getApplication().getName())
                        .content(mapper.writeValueAsString(dto))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithMockJwtUser(username = "admin")
    @Test
    void shouldReturn400ForCreateUser() throws Exception {
        CreateUserRequestDTO dto = new CreateUserRequestDTO();
        dto.setLogin("");
        dto.setName("");
        dto.setConfig(mapper.createObjectNode());

        mvc
                .perform(put("/api/user?app=" + ssoServerProperties.getApplication().getName())
                        .content(mapper.writeValueAsString(dto))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "admin")
    @Test
    void shouldReturn400ForDeleteUser() throws Exception {
        mvc
                .perform(delete("/api/user/dummy")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn403ForDeleteUser() throws Exception {
        mvc
                .perform(delete("/api/user/dummy")
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn400ForPasswordChange() throws Exception {
        mvc
                .perform(post("/api/user/dummy/password/change")
                        .param("oldPassword", "")
                        .param("newPassword", "")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn403ForPasswordReset() throws Exception {
        mvc
                .perform(post("/api/user/dummy/password/reset")
                        .param("newPassword", "")
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithMockJwtUser(username = "admin")
    @Test
    void shouldReturn400ForPasswordReset() throws Exception {
        mvc
                .perform(post("/api/user/dummy/password/reset")
                        .param("newPassword", "")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn400ForConfigUpdate() throws Exception {
        mvc
                .perform(patch("/api/user/dummy/config/dummy")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn403ForConfigDelete() throws Exception {
        mvc
                .perform(delete("/api/user/dummy/config/dummy")
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithMockJwtUser(username = "admin")
    @Test
    void shouldReturn400ForConfigDelete() throws Exception {
        mvc
                .perform(delete("/api/user/dummy/config/dummy")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "user")
    @Test
    void shouldReturn400ForCreateTemporaryUser() throws Exception {
        mvc
                .perform(put("/api/user/temporary")
                        .param("username", "dummy")
                        .param("dateFrom", "0")
                        .param("dateTo", "0")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @WithMockJwtUser(username = "admin")
    @Test
    void shouldReturn403ForRevokeToken() throws Exception {
        mvc
                .perform(post("/api/fast/prepare_logout")
                        .header("Revoke-Token", "")
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }
}
