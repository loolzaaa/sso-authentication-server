package ru.loolzaaa.authserver.config.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.CookieService;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
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
    CookieService cookieService;

    @Mock
    Authentication authentication;

    SsoServerProperties ssoServerProperties;

    LoginAccessFilter loginAccessFilter;

    @BeforeEach
    void setUp() {
        ssoServerProperties = new SsoServerProperties();

        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        loginAccessFilter = new LoginAccessFilter(ssoServerProperties, cookieService);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldContinueFilteringIfRequestPageIsNotLogin(boolean value) throws Exception {
        when(authentication.isAuthenticated()).thenReturn(value);
        when(servletRequest.getRequestURI()).thenReturn(""); // not login
        when(servletRequest.getContextPath()).thenReturn("");

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

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNull() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn(null);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldForwardToLoginIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNotNullAndValid() throws Exception {
        final String CONTINUE_PATH = "aHR0cDovL2V4YW1wbGUuY29tLy90ZXN0L2FwaQ==";
        ArgumentCaptor<String> forwardStringCaptor = ArgumentCaptor.forClass(String.class);
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
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
        final String CONTINUE_PATH = "abcd+efgh";
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn(CONTINUE_PATH);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoMoreInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfNotAuthenticatedAndRequestPageIsLoginAndContinuePathIsNotNullAndInvalidAbsolute() throws Exception {
        final String CONTINUE_PATH = "L3Rlc3QvYXBp";
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn(CONTINUE_PATH);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoMoreInteractions(servletResponse);
    }

    @Test
    void shouldSetStatus307AndRedirectToRootIfAuthenticatedAndRequestToLoginAndContinuePathIsNull() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn(null);
        when(servletResponse.encodeRedirectURL(anyString())).thenReturn("/");
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn("123");
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletResponse).setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        verify(servletResponse).setHeader(eq("Location"), url.capture());
        assertThat(url.getValue()).isEqualTo("/");
        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void shouldSetStatus307AndRedirectToRootIfAuthenticatedAndRequestToLoginAndAccessTokenIsNull() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn("/some/sitr");
        when(servletResponse.encodeRedirectURL(anyString())).thenReturn("/");
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(null);
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletResponse).setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        verify(servletResponse).setHeader(eq("Location"), url.capture());
        assertThat(url.getValue()).isEqualTo("/");
        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void shouldSetStatus307AndRedirectToRootIfAuthenticatedAndRequestToLoginAndContinuePathInvalidScheme() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn("abcd+efgh");
        when(servletResponse.encodeRedirectURL(anyString())).thenReturn("/");
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn("token");
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletResponse).setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        verify(servletResponse).setHeader(eq("Location"), url.capture());
        assertThat(url.getValue()).isEqualTo("/");
        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void shouldSetStatus307AndRedirectToRootIfAuthenticatedAndRequestToLoginAndContinuePathInvalidAbsolute() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn("L3Rlc3QvYXBp");
        when(servletResponse.encodeRedirectURL(anyString())).thenReturn("/");
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn("token");
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletResponse).setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        verify(servletResponse).setHeader(eq("Location"), url.capture());
        assertThat(url.getValue()).isEqualTo("/");
        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
    }

    @Test
    void shouldRedirectToApplicationWithTokenAndServerTimeIfAuthenticatedAndRequestToLoginAndContinuePathValid() throws Exception {
        final String TOKEN = "TOKEN";
        final String ABSOLUTE_URL = "http://example.com/test/api";
        final String ENCODED_URL =  Base64.getUrlEncoder().encodeToString(ABSOLUTE_URL.getBytes());
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(ssoServerProperties.getLoginPage());
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletRequest.getParameter("continue")).thenReturn(ENCODED_URL);
        when(cookieService.getCookieValueByName(eq(CookieName.ACCESS.getName()), any())).thenReturn(TOKEN);
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletResponse).sendRedirect(url.capture());
        assertThat(url.getValue()).startsWith(ABSOLUTE_URL + "?token=" + TOKEN + "&serverTime=");
        verifyNoInteractions(chain);
    }
}