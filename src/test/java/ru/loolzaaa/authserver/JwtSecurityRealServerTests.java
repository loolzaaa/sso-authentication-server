package ru.loolzaaa.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.JWTUtils;
import ru.loolzaaa.authserver.config.security.property.BasicUsersProperties;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.JWTService;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@TestProfiles
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtSecurityRealServerTests {

    @LocalServerPort
    int localPort;

    @Autowired
    TestRestTemplate testRestTemplate;

    @Autowired
    BasicUsersProperties basicUsersProperties;

    @Autowired
    SsoServerProperties ssoServerProperties;

    @Autowired
    JWTUtils jwtUtils;

    String accessToken;
    UUID refreshToken;

    @BeforeEach
    public void setup() {
        Map<String, Object> params = new HashMap<>();
        params.put("login", "user");
        Date now = new Date();
        long accessExp = now.getTime() + jwtUtils.getAccessTokenTtl();

        accessToken = jwtUtils.buildAccessToken(now, accessExp, params);
        refreshToken = UUID.randomUUID();
    }

    // If client application NOT CONTAIN access token, it will redirect to login with continue param,
    // but SSO application can contain access token, so it will try to return it
    @Test
    void shouldRedirectFromLoginToApplicationPageIfServerHasValidAccessToken() {
        final String SSO_URL = String.format("http://localhost:%d%s", localPort, ssoServerProperties.getLoginPage());
        final String APP_URL = "http://example.com";
        final String CONTINUE_PARAM = Base64.getUrlEncoder().encodeToString(APP_URL.getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + accessToken);

        HttpEntity<Void> httpEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = testRestTemplate.exchange(
                String.format("%s?continue=%s", SSO_URL, CONTINUE_PARAM),
                HttpMethod.GET,
                httpEntity,
                String.class);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThat(response.getBody()).contains("Example Domain");
    }

    @Test
    void shouldRedirectFromLoginToMainPageIfServerHasValidAccessToken() {
        final String SSO_URL = String.format("http://localhost:%d%s", localPort, ssoServerProperties.getLoginPage());

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + accessToken);

        HttpEntity<Void> httpEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = testRestTemplate.exchange(
                SSO_URL,
                HttpMethod.GET,
                httpEntity,
                String.class);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThat(response.getBody()).contains("<h5 class=\"lead\">User profile</h5>");
    }

    @Test
    void shouldPassToLoginPageIfServerHasNotValidTokensAndHasFingerprint() {
        final String SSO_URL = String.format("http://localhost:%d%s", localPort, ssoServerProperties.getLoginPage());

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.add(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + "invalid_token");
        headers.add(HttpHeaders.COOKIE, CookieName.REFRESH.getName() + "=" + refreshToken);

        HttpEntity<Void> httpEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = testRestTemplate.exchange(
                String.format("%s?_fingerprint=TEST", SSO_URL),
                HttpMethod.GET,
                httpEntity,
                String.class);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThat(response.getBody()).contains("<label for=\"username\" class=\"form-label\">Username</label>");
    }

    @Test
    void shouldReturn200AndLogoutWithRevokeToken(@Autowired JWTService jwtService) {
        final String SSO_URL = String.format("http://localhost:%d/api/logout?token=%s", localPort, accessToken);
        jwtService.revokeToken(accessToken);

        ResponseEntity<String> response = testRestTemplate.getForEntity(
                SSO_URL,
                String.class);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void shouldLogoutWithRevokeTokenAndRedirectToApplication(@Autowired JWTService jwtService) {
        final String APP_URL = "http://example.com";
        final String CONTINUE_PARAM = Base64.getUrlEncoder().encodeToString(APP_URL.getBytes(StandardCharsets.UTF_8));
        final String SSO_URL = String.format("http://localhost:%d/api/logout?token=%s&continue=%s",
                localPort, accessToken, CONTINUE_PARAM);
        jwtService.revokeToken(accessToken);

        ResponseEntity<String> response = testRestTemplate.getForEntity(
                SSO_URL,
                String.class);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThat(response.getBody()).contains("Example Domain");
    }
}
