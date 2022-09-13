package ru.loolzaaa.authserver.config.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginAccessFilterTest {

    final String MAIN_LOGIN_PAGE = "/login";

    @Mock
    HttpServletRequest servletRequest;
    @Mock
    HttpServletResponse servletResponse;
    @Mock
    FilterChain chain;

    @Mock
    Authentication authentication;

    LoginAccessFilter loginAccessFilter;

    @BeforeEach
    void setUp() {
        SsoServerProperties ssoServerProperties = new SsoServerProperties();

        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        loginAccessFilter = new LoginAccessFilter(ssoServerProperties);
    }

    @Test
    void shouldContinueFilteringIfNotAuthenticated() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(false);
        when(servletRequest.getRequestURI()).thenReturn("");
        when(servletRequest.getContextPath()).thenReturn("");

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfAuthenticatedIsNull() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);
        when(servletRequest.getRequestURI()).thenReturn("");
        when(servletRequest.getContextPath()).thenReturn("");

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldContinueFilteringIfAuthenticatedIsAnonymous() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mock(AnonymousAuthenticationToken.class));
        when(servletRequest.getRequestURI()).thenReturn("");
        when(servletRequest.getContextPath()).thenReturn("");

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(chain).doFilter(servletRequest, servletResponse);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(servletRequest);
        verifyNoInteractions(servletResponse);
    }

    @Test
    void shouldRedirectIfAuthenticatedAndRequestToLogin() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn(MAIN_LOGIN_PAGE);
        when(servletRequest.getContextPath()).thenReturn("");
        when(servletResponse.encodeRedirectURL(anyString())).thenReturn("/");
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);

        loginAccessFilter.doFilter(servletRequest, servletResponse, chain);

        verify(servletResponse).setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        verify(servletResponse).setHeader(eq("Location"), url.capture());
        assertThat(url.getValue()).isEqualTo("/");
    }
}