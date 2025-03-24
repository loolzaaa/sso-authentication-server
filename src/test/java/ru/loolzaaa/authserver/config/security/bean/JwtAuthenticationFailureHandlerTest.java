package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.ServletException;
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.RedirectStrategy;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFailureHandlerTest {

    SsoServerProperties ssoServerProperties;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    AuthenticationException authenticationException;
    @Mock
    RedirectStrategy redirectStrategy;

    JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler;

    @BeforeEach
    void setUp() {
        final String mainLoginPage = "/login";

        ssoServerProperties = new SsoServerProperties();
        ssoServerProperties.setLoginPage(mainLoginPage);

        jwtAuthenticationFailureHandler = new JwtAuthenticationFailureHandler(ssoServerProperties);
        jwtAuthenticationFailureHandler.setRedirectStrategy(redirectStrategy);

        when(authenticationException.getLocalizedMessage()).thenReturn("ERROR");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void shouldRedirectToDefaultUrl(int op) throws IOException, ServletException {
        when(req.getParameter("_app")).thenReturn(op == 0 ? null : "APP");
        when(req.getParameter("_continue")).thenReturn(op == 0 ? "CONTINUE" : null);
        when(req.getSession(anyBoolean())).thenReturn(null);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        jwtAuthenticationFailureHandler.onAuthenticationFailure(req, resp, authenticationException);

        verify(redirectStrategy).sendRedirect(any(), any(), captor.capture());
        assertThat(captor.getValue()).startsWith(ssoServerProperties.getLoginPage() + "?credentialsError=");
    }

    @Test
    void shouldAppendContinueParamToDefaultUrl() throws IOException, ServletException {
        final String app = "APP";
        final String continuePath = "CONTINUE";
        when(req.getParameter("_app")).thenReturn(app);
        when(req.getParameter("_continue")).thenReturn(continuePath);
        when(req.getSession(anyBoolean())).thenReturn(null);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        jwtAuthenticationFailureHandler.onAuthenticationFailure(req, resp, authenticationException);

        verify(redirectStrategy).sendRedirect(any(), any(), captor.capture());
        assertThat(captor.getValue()).startsWith(ssoServerProperties.getLoginPage() + "?credentialsError=");
        assertThat(captor.getValue()).contains("&continue=" + continuePath);
    }
}