package ru.loolzaaa.authserver;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.MessageSource;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.JWTUtils;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.JWTService;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

@TestProfiles
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "server.servlet.contextPath=/")
class JwtSecurityRealServerTests {

    @LocalServerPort
    int localPort;

    TestRestTemplate testRestTemplate;

    @Autowired
    SsoServerProperties ssoServerProperties;

    @Autowired
    JWTUtils jwtUtils;

    @Autowired
    MessageSource messageSource;

    @Autowired
    JdbcTemplate jdbcTemplate;

    String accessToken;
    UUID refreshToken;

    @BeforeEach
    public void setup() {
        testRestTemplate = new TestRestTemplate(TestRestTemplate.HttpClientOption.ENABLE_REDIRECTS);

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
        assertThat(response.getBody())
                .contains("name=\"username\"")
                .contains("name=\"password\"");
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

    @Test
    void shouldPreserveAppParameterWhenRedirectingToRefreshForBrowserRequest() {
        final String LOGIN = "user";
        final String APP = "system5s";
        final String APP_URL = "http://example.com/app";
        final String CONTINUE_PARAM = Base64.getUrlEncoder().encodeToString(APP_URL.getBytes(StandardCharsets.UTF_8));
        final String SSO_URL = String.format("http://localhost:%d%s?app=%s&continue=%s",
                localPort, ssoServerProperties.getLoginPage(), APP, CONTINUE_PARAM);

        Date issuedAt = new Date(System.currentTimeMillis() - 7_200_000L);
        long accessExp = System.currentTimeMillis() - 3_600_000L;
        Map<String, Object> params = new HashMap<>();
        params.put("login", LOGIN);
        params.put("authorities", List.of("passport"));
        String expiredAccessToken = jwtUtils.buildAccessToken(issuedAt, accessExp, params);

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        headers.add(HttpHeaders.COOKIE, CookieName.ACCESS.getName() + "=" + expiredAccessToken);
        headers.add(HttpHeaders.COOKIE, CookieName.REFRESH.getName() + "=" + UUID.randomUUID());

        HttpEntity<Void> httpEntity = new HttpEntity<>(headers);
        ResponseEntity<String> response = new TestRestTemplate().exchange(
                SSO_URL,
                HttpMethod.GET,
                httpEntity,
                String.class);

        assertNotNull(response);
        assertThat(response.getStatusCode().is3xxRedirection()).isTrue();
        String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
        assertThat(location)
                .contains(ssoServerProperties.getRefreshUri())
                .contains("continue=")
                .contains("app=" + APP);
    }

    @Test
    void shouldReturnForbiddenAndExtendSsoSessionWhenRefreshAppWithoutAccess() {
        final String LOGIN = "user";
        final String APP = "system5s";
        final String FINGERPRINT = "REFRESH_FORBIDDEN_FP";
        final String APP_URL = "http://example.com/app";
        final String CONTINUE_PARAM = Base64.getUrlEncoder().encodeToString(APP_URL.getBytes(StandardCharsets.UTF_8));

        UUID validRefreshToken = UUID.randomUUID();
        Long userId = jdbcTemplate.queryForObject("SELECT id FROM users WHERE login = ?", Long.class, LOGIN);
        jdbcTemplate.update("INSERT INTO refresh_sessions (user_id, refresh_token, fingerprint, expires_in) " +
                        "VALUES (?, ?::uuid, ?, ?)",
                userId, validRefreshToken.toString(), FINGERPRINT,
                new Timestamp(System.currentTimeMillis() + 3_600_000L));

        try {
            Date issuedAt = new Date(System.currentTimeMillis() - 7_200_000L);
            long accessExp = System.currentTimeMillis() - 3_600_000L;
            Map<String, Object> params = new HashMap<>();
            params.put("login", LOGIN);
            params.put("authorities", List.of("passport"));
            String expiredAccessToken = jwtUtils.buildAccessToken(issuedAt, accessExp, params);

            String accessCookie = CookieName.ACCESS.getName() + "=" + expiredAccessToken;
            String refreshCookie = CookieName.REFRESH.getName() + "=" + validRefreshToken;
            TestRestTemplate restTemplate = new TestRestTemplate();

            HttpHeaders pageHeaders = new HttpHeaders();
            pageHeaders.setAccept(List.of(MediaType.TEXT_HTML));
            pageHeaders.add(HttpHeaders.COOKIE, accessCookie + "; " + refreshCookie);
            ResponseEntity<String> refreshPage = restTemplate.exchange(
                    String.format("http://localhost:%d%s?continue=%s&app=%s",
                            localPort, ssoServerProperties.getRefreshUri(), CONTINUE_PARAM, APP),
                    HttpMethod.GET,
                    new HttpEntity<>(pageHeaders),
                    String.class);

            assertEquals(HttpStatus.OK, refreshPage.getStatusCode());
            String csrfToken = extractCsrfToken(refreshPage.getBody());
            assertThat(csrfToken).isNotBlank();

            HttpHeaders postHeaders = new HttpHeaders();
            postHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            postHeaders.add(HttpHeaders.COOKIE,
                    accessCookie + "; " + refreshCookie + "; " + extractResponseCookies(refreshPage));

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("_csrf", csrfToken);
            form.add("_fingerprint", FINGERPRINT);
            form.add("_app", APP);
            form.add("_continue", CONTINUE_PARAM);

            ResponseEntity<String> response = restTemplate.exchange(
                    String.format("http://localhost:%d/api/refresh", localPort),
                    HttpMethod.POST,
                    new HttpEntity<>(form, postHeaders),
                    String.class);

            assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
            assertNull(response.getHeaders().getFirst(HttpHeaders.LOCATION));
            assertThat(response.getBody())
                    .contains("There is no application [" + APP + "] for user [" + LOGIN + "]");

            List<String> setCookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
            assertNotNull(setCookies);
            assertThat(setCookies.stream()
                    .anyMatch(cookie -> cookie.startsWith(CookieName.ACCESS.getName() + "="))).isTrue();
            assertThat(setCookies.stream()
                    .anyMatch(cookie -> cookie.startsWith(CookieName.REFRESH.getName() + "="))).isTrue();
        } finally {
            jdbcTemplate.update("DELETE FROM refresh_sessions WHERE fingerprint = ?", FINGERPRINT);
        }
    }

    private String extractCsrfToken(String html) {
        if (html == null) {
            return null;
        }
        Matcher inputMatcher = Pattern.compile("<input[^>]*>").matcher(html);
        while (inputMatcher.find()) {
            String input = inputMatcher.group();
            if (input.contains("name=\"_csrf\"")) {
                Matcher valueMatcher = Pattern.compile("value=\"([^\"]+)\"").matcher(input);
                if (valueMatcher.find()) {
                    return valueMatcher.group(1);
                }
            }
        }
        return null;
    }

    private String extractResponseCookies(ResponseEntity<?> response) {
        List<String> setCookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        if (setCookies == null) {
            return "";
        }
        return setCookies.stream()
                .map(header -> header.split(";", 2)[0])
                .collect(Collectors.joining("; "));
    }
}
