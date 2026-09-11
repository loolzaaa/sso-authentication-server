package ru.loolzaaa.authserver;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.JWTUtils;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@TestProfiles
@SpringBootTest
@TestPropertySource(properties = "server.servlet.contextPath=/")
class RefreshAccessFlowIntegrationTest {

    private static final String LOGIN = "user";
    private static final String APP_WITHOUT_ACCESS = "system5s";
    private static final String FINGERPRINT = "TEST_FP";

    @Autowired
    WebApplicationContext context;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    JWTUtils jwtUtils;

    @Autowired
    SsoServerProperties ssoServerProperties;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.update("DELETE FROM refresh_sessions WHERE fingerprint = ?", FINGERPRINT);
    }

    @Test
    void shouldRedirectToForbiddenWhenRefreshAppWithoutAccess() throws Exception {
        UUID refreshToken = UUID.randomUUID();
        Long userId = jdbcTemplate.queryForObject("SELECT id FROM users WHERE login = ?", Long.class, LOGIN);

        jdbcTemplate.update("INSERT INTO refresh_sessions (user_id, refresh_token, fingerprint, expires_in) " +
                        "VALUES (?, ?::uuid, ?, ?)",
                userId, refreshToken.toString(), FINGERPRINT,
                new Timestamp(System.currentTimeMillis() + 3_600_000L));

        Date issuedAt = new Date(System.currentTimeMillis() - 7_200_000L);
        long accessExp = System.currentTimeMillis() - 3_600_000L;
        Map<String, Object> params = Map.of("login", LOGIN, "authorities", List.of("passport"));
        String expiredAccessToken = jwtUtils.buildAccessToken(issuedAt, accessExp, params);

        mvc.perform(post("/api/refresh")
                        .param("_fingerprint", FINGERPRINT)
                        .param("_app", APP_WITHOUT_ACCESS)
                        .cookie(new Cookie(CookieName.ACCESS.getName(), expiredAccessToken))
                        .cookie(new Cookie(CookieName.REFRESH.getName(), refreshToken.toString()))
                        .with(csrf()))
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl(ssoServerProperties.getForbiddenUri()))
                .andExpect(cookie().exists(CookieName.ACCESS.getName()))
                .andExpect(cookie().exists(CookieName.REFRESH.getName()));
    }
}
