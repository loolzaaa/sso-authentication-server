package ru.loolzaaa.authserver.config.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.bean.IgnoredPathsHandler;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

    final String REFRESH_TOKEN_URI = "/trefresh";

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
    }

    @Test
    void shouldContinueFilteringIfAccessTokenIsNull() throws Exception {
        when(req.getContextPath()).thenReturn("");
        when(req.getRequestURI()).thenReturn("/uri");
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
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

        verify(securityContextService).updateSecurityContextHolder(req, resp, LOGIN);
        verify(filterChain).doFilter(req, resp);
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
        when(req.getParameter(eq("_fingerprint"))).thenReturn("FINGERPRINT");
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);
        when(jwtService.refreshAccessToken(req, resp, INVALID_REFRESH_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).clearSecurityContextHolder(req, resp);
        verify(filterChain).doFilter(req, resp);
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
        when(req.getParameter(eq("_fingerprint"))).thenReturn("FINGERPRINT");
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);
        when(jwtService.refreshAccessToken(req, resp, VALID_REFRESH_TOKEN)).thenReturn(jwtAuthentication);
        when(jwtAuthentication.getUsername()).thenReturn(LOGIN);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).updateSecurityContextHolder(req, resp, LOGIN);
        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
    }

    // Request NOT saved!
    @Test
    void shouldSaveRequestAndRedirectForFingerprintIfContinuePathIsNotNull() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String VALID_REFRESH_TOKEN = "VALID_REFRESH_TOKEN";
        final String CONTEXT_PATH = "/context-path";
        final String CONTINUE_PATH = "http://some-site.com/uri";
        ArgumentCaptor<String> redirectUrlCaptor = ArgumentCaptor.forClass(String.class);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(VALID_REFRESH_TOKEN);
        when(req.getParameter(eq("_fingerprint"))).thenReturn(null);
        when(req.getParameter(eq("continue"))).thenReturn(CONTINUE_PATH);
        when(req.getContextPath()).thenReturn(CONTEXT_PATH);
        when(req.getScheme()).thenReturn("http");
        when(req.getServerName()).thenReturn("some-site.com");
        when(req.getServerPort()).thenReturn(8080);
        when(req.getRequestURI()).thenReturn(CONTEXT_PATH + "/some-uri");
        when(req.getQueryString()).thenReturn("");
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        String fullRequestUrl = UrlUtils.buildFullRequestUrl(req);
        String requestUrl = fullRequestUrl.substring(0, fullRequestUrl.indexOf(req.getContextPath()));
        String redirectURL = UriComponentsBuilder.fromHttpUrl(requestUrl + CONTEXT_PATH + REFRESH_TOKEN_URI)
                .queryParam("continue", CONTINUE_PATH)
                .toUriString();

        verify(resp).sendRedirect(redirectUrlCaptor.capture());
        assertThat(redirectUrlCaptor.getValue()).isEqualTo(redirectURL);
        verifyNoInteractions(filterChain);
    }

    // Request NOT saved!
    @Test
    void shouldSaveRequestAndRedirectForFingerprintIfContinuePathIsNull() throws Exception {
        final String INVALID_ACCESS_TOKEN = "INVALID_ACCESS_TOKEN";
        final String VALID_REFRESH_TOKEN = "VALID_REFRESH_TOKEN";
        final String CONTEXT_PATH = "/context-path";
        ArgumentCaptor<String> redirectUrlCaptor = ArgumentCaptor.forClass(String.class);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(INVALID_ACCESS_TOKEN);
        when(cookieService.getCookieValueByName(eq(CookieName.REFRESH.getName()), any())).thenReturn(VALID_REFRESH_TOKEN);
        when(req.getParameter(eq("_fingerprint"))).thenReturn(null);
        when(req.getParameter(eq("continue"))).thenReturn(null);
        when(req.getContextPath()).thenReturn(CONTEXT_PATH);
        when(req.getRequestURI()).thenReturn(CONTEXT_PATH + "/uri");
        when(jwtService.checkAccessToken(INVALID_ACCESS_TOKEN)).thenReturn(null);

        jwtTokenFilter.doFilterInternal(req, resp, filterChain);

        verify(resp).sendRedirect(redirectUrlCaptor.capture());
        assertThat(redirectUrlCaptor.getValue()).isEqualTo(CONTEXT_PATH + REFRESH_TOKEN_URI);
        verifyNoInteractions(filterChain);
    }
}