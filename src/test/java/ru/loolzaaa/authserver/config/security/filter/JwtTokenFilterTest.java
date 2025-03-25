package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.bean.IgnoredPathsHandler;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

    SsoServerProperties ssoServerProperties;

    @Mock
    SecurityContextService securityContextService;
    @Mock
    JWTService jwtService;
    @Mock
    CookieService cookieService;

    @Mock
    JWTAuthentication jwtAuthentication;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain filterChain;

    JwtTokenFilter jwtTokenFilter;

    @BeforeEach
    void setUp() {
        ssoServerProperties = new SsoServerProperties();

        IgnoredPathsHandler ignoredPathsHandler = new IgnoredPathsHandler(ssoServerProperties);

        jwtTokenFilter = new JwtTokenFilter(ssoServerProperties, ignoredPathsHandler, securityContextService, jwtService, cookieService);
    }

    @Test
    void shouldContinueFilteringIfRequestUriIsIgnored() throws Exception {
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn(ssoServerProperties.getRefreshUri());

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
        verifyNoInteractions(cookieService);
        verifyNoInteractions(securityContextService);
    }

    @Test
    void shouldContinueFilteringIfAccessTokenIsNull() throws Exception {
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/uri");
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
        verifyNoInteractions(securityContextService);
    }

    @Test
    void shouldUpdateSecurityContextAndContinueFilteringWhenCorrectAccessToken() throws Exception {
        final String VALID_ACCESS_TOKEN = "VALID_ACCESS_TOKEN";
        final String LOGIN = "LOGIN";
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/uri");
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(VALID_ACCESS_TOKEN);
        when(jwtService.checkAccessToken(VALID_ACCESS_TOKEN)).thenReturn(LOGIN);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).updateSecurityContextHolder(req, LOGIN);
        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(securityContextService);
        verifyNoMoreInteractions(filterChain);
    }

    @Test
    void shouldClearSecurityContextAndContinueFilteringWhenIncorrectAccessTokenAndRefreshTokenIsNull() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/uri");
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(null);
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).clearSecurityContextHolder(req, resp);
        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(securityContextService);
        verifyNoMoreInteractions(filterChain);
    }

    @Test
    void shouldClearSecurityContextAndContinueFilteringWhenIncorrectAccessTokenAndIncorrectRefreshToken() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String INVALID_REFRESH_TOKEN = "INVALID_REFRESH_TOKEN";
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(INVALID_REFRESH_TOKEN);
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/uri");
        when(req.getParameter("_fingerprint")).thenReturn("FINGERPRINT");
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);
        when(jwtService.refreshAccessToken(req, resp, INVALID_ACCESS_TOKEN, INVALID_REFRESH_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).clearSecurityContextHolder(req, resp);
        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(securityContextService);
        verifyNoMoreInteractions(filterChain);
    }

    @Test
    void shouldUpdateSecurityContextAndContinueFilteringWhenIncorrectAccessTokenAndCorrectRefreshToken() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String VALID_REFRESH_TOKEN = "VALID_REFRESH_TOKEN";
        final String LOGIN = "LOGIN";
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(VALID_REFRESH_TOKEN);
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/uri");
        when(req.getParameter("_fingerprint")).thenReturn("FINGERPRINT");
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);
        when(jwtService.refreshAccessToken(req, resp, INVALID_ACCESS_TOKEN, VALID_REFRESH_TOKEN)).thenReturn(jwtAuthentication);
        when(jwtAuthentication.getUsername()).thenReturn(LOGIN);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).updateSecurityContextHolder(req, LOGIN);
        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(securityContextService);
        verifyNoMoreInteractions(filterChain);
    }

    @Test
    void shouldSetForbiddenStatusAndFingerprintHeaderIfAjaxRequest() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String VALID_REFRESH_TOKEN = "VALID_REFRESH_TOKEN";
        final String CONTEXT_PATH = "/context-path";
        final String AJAX_HEADER = "application/json; charset=utf-8";
        ArgumentCaptor<String> fingerprintHeaderCaptor = ArgumentCaptor.forClass(String.class);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(VALID_REFRESH_TOKEN);
        when(req.getParameter("_fingerprint")).thenReturn(null);
        when(req.getContextPath()).thenReturn(CONTEXT_PATH);
        when(req.getScheme()).thenReturn("http");
        when(req.getServerName()).thenReturn("some-site.com");
        when(req.getServerPort()).thenReturn(8080);
        when(req.getRequestURI()).thenReturn(CONTEXT_PATH + "/some-uri");
        when(req.getQueryString()).thenReturn("");
        when(req.getHeader("Accept")).thenReturn(AJAX_HEADER);
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(resp).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(resp).setHeader(eq("X-SSO-FP"), fingerprintHeaderCaptor.capture());
        assertThat(fingerprintHeaderCaptor.getValue()).isEqualTo("http://some-site.com:8080" + CONTEXT_PATH + "/api/refresh/ajax");
        verifyNoInteractions(filterChain);
    }

    @Test
    void shouldRedirectForFingerprintIfBrowserRequestAndContinuePathIsNull() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String VALID_REFRESH_TOKEN = "VALID_REFRESH_TOKEN";
        final String CONTEXT_PATH = "/context-path";
        final String BROWSER_HEADER = "text/html; charset=utf-8";
        final String encodedPath = URLEncoder.encode(Base64.getUrlEncoder()
                .encodeToString("http://null:0/context-path/some-uri".getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        ArgumentCaptor<String> redirectUrlCaptor = ArgumentCaptor.forClass(String.class);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(VALID_REFRESH_TOKEN);
        when(req.getScheme()).thenReturn("http");
        when(req.getParameter("_fingerprint")).thenReturn(null);
        when(req.getParameter("continue")).thenReturn(null);
        when(req.getContextPath()).thenReturn(CONTEXT_PATH);
        when(req.getRequestURI()).thenReturn(CONTEXT_PATH + "/some-uri");
        when(req.getHeader("Accept")).thenReturn(BROWSER_HEADER);
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(resp).sendRedirect(redirectUrlCaptor.capture());
        assertThat(redirectUrlCaptor.getValue())
                .isEqualTo(CONTEXT_PATH + ssoServerProperties.getRefreshUri() + "?continue=" + encodedPath);
        verifyNoInteractions(filterChain);
    }

    @Test
    void shouldRedirectWithContinuePathForFingerprintIfBrowserRequest() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String VALID_REFRESH_TOKEN = "VALID_REFRESH_TOKEN";
        final String CONTEXT_PATH = "/context-path";
        final String BROWSER_HEADER = "text/html; charset=utf-8";
        final String CONTINUE_PATH = "aHR0cDovL2V4YW1wbGUuY29tLy90ZXN0L2FwaQ";
        final String REDIRECT_URL = "http://some-site.com:8080" + CONTEXT_PATH + ssoServerProperties.getRefreshUri() +
                "?continue=" + CONTINUE_PATH;
        ArgumentCaptor<String> redirectUrlCaptor = ArgumentCaptor.forClass(String.class);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(VALID_REFRESH_TOKEN);
        when(req.getParameter("_fingerprint")).thenReturn(null);
        when(req.getParameter("continue")).thenReturn(CONTINUE_PATH);
        when(req.getContextPath()).thenReturn(CONTEXT_PATH);
        when(req.getScheme()).thenReturn("http");
        when(req.getServerName()).thenReturn("some-site.com");
        when(req.getServerPort()).thenReturn(8080);
        when(req.getRequestURI()).thenReturn(CONTEXT_PATH + "/some-uri");
        when(req.getQueryString()).thenReturn("");
        when(req.getHeader("Accept")).thenReturn(BROWSER_HEADER);
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(resp).sendRedirect(redirectUrlCaptor.capture());
        assertThat(redirectUrlCaptor.getValue()).isEqualTo(REDIRECT_URL);
        verifyNoInteractions(filterChain);
    }
}