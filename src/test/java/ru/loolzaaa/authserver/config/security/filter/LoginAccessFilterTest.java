package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginAccessFilterTest {

    @Mock
    HttpServletRequest servletRequest;
    @Mock
    HttpServletResponse servletResponse;
    @Mock
    FilterChain chain;

    @Mock
    AccessDeniedHandler accessDeniedHandler;
    @Mock
    CookieService cookieService;
    @Mock
    JWTService jwtService;

    @Mock
    Authentication authentication;

    SsoServerProperties ssoServerProperties;

    LoginAccessFilter loginAccessFilter;

    @BeforeEach
    void setUp() {
        ssoServerProperties = new SsoServerProperties();

        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        loginAccessFilter = new LoginAccessFilter(ssoServerProperties, accessDeniedHandler, cookieService, jwtService);
    }

    @Test
    void shouldCheckLoginPage() {
        ssoServerProperties.setLoginPage("");

        assertThatThrownBy(() -> loginAccessFilter.initFilterBean())
                .isInstanceOf(IllegalArgumentException.class);

        ssoServerProperties.setLoginPage(null);

        assertThatThrownBy(() -> loginAccessFilter.initFilterBean())
                .isInstanceOf(IllegalArgumentException.class);

        ssoServerProperties.setLoginPage("ERROR");

        assertThatThrownBy(() -> loginAccessFilter.initFilterBean())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldContinueFilteringIfRequestPageIsNotLogin(boolean value) throws Exception {
        when(authentication.isAuthenticated()).thenReturn(value);
        when(servletRequest.getRequestURI()).thenReturn(""); // not login
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(value ? "APP" : null);
        when(servletRequest.getParameter("continue")).thenReturn(value ? null : "CONTINUE");

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfAuthenticatedIsNullAndRequestPageIsNotLogin() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(""); // not login
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(null);
        when(servletRequest.getParameter("continue")).thenReturn("CONTINUE");

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfAuthenticatedIsAnonymousAndRequestPageIsNotLogin() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mock(AnonymousAuthenticationToken.class));
        when(servletRequest.getRequestURI()).thenReturn(""); // not login
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(null);
        when(servletRequest.getParameter("continue")).thenReturn("CONTINUE");

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void shouldContinueFilteringIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNull(int op) throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(op == 0 ? null : "APP");
        when(servletRequest.getParameter("continue")).thenReturn(op == 0 ? "CONTINUE" : null);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldForwardToLoginIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNotNullAndValid() throws Exception {
        final String APP = "APP";
        final String CONTINUE_PATH = "aHR0cDovL2V4YW1wbGUuY29tLy90ZXN0L2FwaQ==";
        ArgumentCaptor<String> forwardStringCaptor = ArgumentCaptor.forClass(String.class);
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(APP);
        when(servletRequest.getParameter("continue")).thenReturn(CONTINUE_PATH);
        RequestDispatcher requestDispatcher = mock(RequestDispatcher.class);
        when(servletRequest.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletRequest).getRequestDispatcher(forwardStringCaptor.capture());
        verify(requestDispatcher).forward(servletRequest, servletResponse);
        assertThat(forwardStringCaptor.getValue()).isEqualTo(ssoServerProperties.getLoginPage());
        verifyNoInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoMoreInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNotNullAndInvalidScheme() throws Exception {
        final String APP = "APP";
        final String CONTINUE_PATH = "abcd+efgh";
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(APP);
        when(servletRequest.getParameter("continue")).thenReturn(CONTINUE_PATH);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoMoreInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNotNullAndInvalidAbsolute() throws Exception {
        final String APP = "APP";
        final String CONTINUE_PATH = "L3Rlc3QvYXBp";
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(APP);
        when(servletRequest.getParameter("continue")).thenReturn(CONTINUE_PATH);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoMoreInteractions(servletResponse);
    }

    @Test
    void shouldRedirectToApplicationWithTokenAndServerTimeIfAuthenticatedAndRequestToLoginAndContinuePathValid() throws Exception {
        final String APP = "APP";
        final String TOKEN = "TOKEN";
        final String TOKEN2 = "TOKEN2";
        final String ABSOLUTE_URL = "http://example.com/test/api";
        final String ENCODED_URL =  Base64.getUrlEncoder().encodeToString(ABSOLUTE_URL.getBytes());
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(APP);
        when(servletRequest.getParameter("continue")).thenReturn(ENCODED_URL);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(TOKEN);
        when(jwtService.authenticateWithJWT(eq(servletRequest), eq(authentication), anyString())).thenReturn(TOKEN2);
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(jwtService).authenticateWithJWT(servletRequest, authentication, APP);
        verify(servletResponse).sendRedirect(url.capture());
        assertThat(url.getValue()).startsWith(ABSOLUTE_URL + "?token=" + TOKEN2 + "&serverTime=");
        verifyNoInteractions(chain);
    }

    @Test
    void shouldHandleAccessDeniedIfAuthenticatedButAppForbidden() throws Exception {
        final String APP = "APP";
        final String TOKEN = "TOKEN";
        final String ABSOLUTE_URL = "http://example.com/test/api";
        final String ENCODED_URL =  Base64.getUrlEncoder().encodeToString(ABSOLUTE_URL.getBytes());
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("app")).thenReturn(APP);
        when(servletRequest.getParameter("continue")).thenReturn(ENCODED_URL);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(TOKEN);
        when(jwtService.authenticateWithJWT(eq(servletRequest), eq(authentication), anyString()))
                .thenThrow(IllegalArgumentException.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(jwtService).authenticateWithJWT(servletRequest, authentication, APP);
        verify(accessDeniedHandler).handle(eq(servletRequest), eq(servletResponse), any());
        verifyNoInteractions(chain);
    }
}