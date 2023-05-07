package ru.loolzaaa.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.MessageSource;
import org.springframework.http.*;
import org.springframework.test.context.TestPropertySource;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.JWTUtils;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.JWTService;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@TestProfiles
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "server.servlet.contextPath=/")
class JwtSecurityRealServerTests {

    @LocalServerPort
    int localPort;

    @Autowired
    TestRestTemplate testRestTemplate;

    @Autowired
    SsoServerProperties ssoServerProperties;

    @Autowired
    JWTUtils jwtUtils;

    @Autowired
    MessageSource messageSource;

    String accessToken;
    UUID refreshToken;

    @BeforeEach
    public void setup() {
        Map<String, Object> params = new HashMap<>();
        params.put("login", "user");
        params.put("authorities", List.of("passport"));
        Date now = new Date();
        long accessExp = now.getTime() + jwtUtils.getAccessTokenTtl().toMillis();

        accessToken = jwtUtils.buildAccessToken(now, accessExp, params);
        refreshToken = UUID.randomUUID();
    }

    // If client application NOT CONTAIN access token, it will redirect to login with continue param,
    // but SSO application can contain access token, so it will try to return it
    @Test
    void shouldRedirectFromLoginToApplicationPageIfServerHasValidAccessToken() {
        final String SSO_URL = String.format("http://localhost:%d%s", localPort, ssoServerProperties.getLoginPage());
        final String APP_URL = "http://example.com";
        final String APP = "passport";
        final String CONTINUE_PARAM = Base64.getUrlEncoder().encodeToString(APP_URL.getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + accessToken);

        HttpEntity<Void> httpEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = testRestTemplate.exchange(
                String.format("%s?app=%s&continue=%s", SSO_URL, APP, CONTINUE_PARAM),
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
        final String expectedText = messageSource.getMessage("index.title", null, Locale.US);

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
        assertThat(response.getBody()).contains(String.format("<h5 class=\"lead\">%s</h5>", expectedText));
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
        assertThat(response.getBody()).contains("<input type=\"text\" name=\"username\" class=\"form-control\" id=\"username\">");
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
        final String APP = "passport";
        final String APP_URL = "http://example.com";
        final String CONTINUE_PARAM = Base64.getUrlEncoder().encodeToString(APP_URL.getBytes(StandardCharsets.UTF_8));
        final String SSO_URL = String.format("http://localhost:%d/api/logout?token=%s&app=%s&continue=%s",
                localPort, accessToken, APP, CONTINUE_PARAM);
        jwtService.revokeToken(accessToken);

        ResponseEntity<String> response = testRestTemplate.getForEntity(
                SSO_URL,
                String.class);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThat(response.getBody()).contains("Example Domain");
    }
}
