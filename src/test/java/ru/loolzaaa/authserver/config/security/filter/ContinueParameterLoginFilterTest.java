package ru.loolzaaa.authserver.config.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ContinueParameterLoginFilterTest {

    final String LOGIN_FORM_URL = "/login";

    @Mock
    HttpServletRequest req;
    @Mock
    ServletResponse resp;
    @Mock
    FilterChain chain;

    @Mock
    RequestDispatcher requestDispatcher;

    @Mock
    Authentication authentication;

    ContinueParameterLoginFilter continueParameterLoginFilter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        continueParameterLoginFilter = new ContinueParameterLoginFilter(LOGIN_FORM_URL);

        when(req.getParameter(anyString())).thenReturn("/");
    }

    @Test
    void shouldContinueFilteringIfContinueParameterIsNull() throws Exception {
        when(req.getParameter(anyString())).thenReturn(null);

        continueParameterLoginFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(req);
        verifyNoInteractions(resp);
    }

    @Test
    void shouldContinueFilteringIfAlreadyAuthenticated() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);

        continueParameterLoginFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(req);
        verifyNoInteractions(resp);
    }

    @Test
    void shouldContinueFilteringIfRequestUriIsNotEqualToFormLogin() throws Exception {
        when(req.getParameter(anyString())).thenReturn(LOGIN_FORM_URL);
        when(req.getRequestURI()).thenReturn(LOGIN_FORM_URL);

        continueParameterLoginFilter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verifyNoMoreInteractions(chain);
        verifyNoMoreInteractions(req);
        verifyNoInteractions(resp);
    }

    @Test
    void shouldForwardRequestIfAuthenticationIsNull() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);
        when(req.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);

        continueParameterLoginFilter.doFilter(req, resp, chain);

        verify(requestDispatcher).forward(req, resp);
        verifyNoMoreInteractions(requestDispatcher);
        verifyNoInteractions(resp);
        verifyNoInteractions(chain);
    }

    @Test
    void shouldForwardRequestIfAuthenticationIsAnonymous() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mock(AnonymousAuthenticationToken.class));
        when(req.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);

        continueParameterLoginFilter.doFilter(req, resp, chain);

        verify(requestDispatcher).forward(req, resp);
        verifyNoMoreInteractions(requestDispatcher);
        verifyNoInteractions(resp);
        verifyNoInteractions(chain);
    }

    @Test
    void shouldForwardRequestIfNotAuthenticated() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(false);
        when(req.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);

        continueParameterLoginFilter.doFilter(req, resp, chain);

        verify(requestDispatcher).forward(req, resp);
        verifyNoMoreInteractions(requestDispatcher);
        verifyNoInteractions(resp);
        verifyNoInteractions(chain);
    }
}