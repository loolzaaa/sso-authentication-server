package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.test.util.ReflectionTestUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFailureHandlerTest {

    final String mainLoginPage = "/login";

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    AuthenticationException authenticationException;
    @Mock
    HttpSession httpSession;
    @Mock
    RedirectStrategy redirectStrategy;

    JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler;

    @BeforeEach
    void setUp() {
        jwtAuthenticationFailureHandler = new JwtAuthenticationFailureHandler();
        jwtAuthenticationFailureHandler.setRedirectStrategy(redirectStrategy);

        ReflectionTestUtils.setField(jwtAuthenticationFailureHandler, "mainLoginPage", mainLoginPage);
    }

    @Test
    void shouldRedirectToDefaultUrl() throws IOException, ServletException {
        when(req.getParameter("_continue")).thenReturn(null);
        when(req.getSession(anyBoolean())).thenReturn(httpSession);
        when(req.getSession()).thenReturn(httpSession);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        jwtAuthenticationFailureHandler.onAuthenticationFailure(req, resp, authenticationException);

        verify(redirectStrategy).sendRedirect(any(), any(), captor.capture());
        assertThat(captor.getValue()).isEqualTo(mainLoginPage + "?credentialsError");
    }

    @Test
    void shouldAppendContinueParamToDefaultUrl() throws IOException, ServletException {
        final String continuePath = "CONTINUE";
        when(req.getParameter("_continue")).thenReturn(continuePath);
        when(req.getSession(anyBoolean())).thenReturn(httpSession);
        when(req.getSession()).thenReturn(httpSession);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        jwtAuthenticationFailureHandler.onAuthenticationFailure(req, resp, authenticationException);

        verify(redirectStrategy).sendRedirect(any(), any(), captor.capture());
        assertThat(captor.getValue()).isEqualTo(mainLoginPage + "?credentialsError" + "&continue=" + continuePath);
    }
}