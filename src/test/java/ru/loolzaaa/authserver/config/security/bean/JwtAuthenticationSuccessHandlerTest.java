package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import ru.loolzaaa.authserver.services.JWTService;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationSuccessHandlerTest {

    final String token = "TOKEN";

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    Authentication authentication;

    @Mock
    JWTService jwtService;

    JwtAuthenticationSuccessHandler successHandler;

    @BeforeEach
    void setUp() {
        successHandler = new JwtAuthenticationSuccessHandler(jwtService);

        when(jwtService.authenticateWithJWT(eq(req), eq(resp), eq(authentication), anyString())).thenReturn(token);
        lenient().when(jwtService.authenticateWithJWT(eq(req), eq(authentication), anyString())).thenReturn(token);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".invalid-base64-string-because-of-start-dot"})
    void shouldUseSuperClassMethodWhenAppIsNull(String path) throws Exception {
        final String fingerprint = "FP";
        if ("".equals(path)) path = null;
        when(req.getParameter("_app")).thenReturn(null);
        when(req.getParameter("_continue")).thenReturn(path);
        when(req.getParameter("_fingerprint")).thenReturn(fingerprint);

        successHandler.onAuthenticationSuccess(req, resp, authentication);

        verify(jwtService).authenticateWithJWT(req, resp, authentication, fingerprint);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".invalid-base64-string-because-of-start-dot"})
    void shouldUseSuperClassMethodWhenContinuePathIsNotBase64(String path) throws Exception {
        final String fingerprint = "FP";
        if ("".equals(path)) path = null;
        when(req.getParameter("_app")).thenReturn("APP");
        when(req.getParameter("_continue")).thenReturn(path);
        when(req.getParameter("_fingerprint")).thenReturn(fingerprint);

        successHandler.onAuthenticationSuccess(req, resp, authentication);

        verify(jwtService).authenticateWithJWT(req, resp, authentication, fingerprint);
    }

    @ParameterizedTest
    @MethodSource("getInvalidUrls")
    void shouldUseSuperClassMethodWhenContinuePathIsEmptyOrInvalid(String path) throws Exception {
        final String fingerprint = "FP";
        when(req.getParameter("_app")).thenReturn("APP");
        when(req.getParameter("_continue")).thenReturn(path);
        when(req.getParameter("_fingerprint")).thenReturn(fingerprint);

        successHandler.onAuthenticationSuccess(req, resp, authentication);

        verify(jwtService).authenticateWithJWT(req, resp, authentication, fingerprint);
    }

    @ParameterizedTest
    @MethodSource("getValidUrls")
    void shouldRedirectWhenContinuePathIsValid(String path) throws Exception {
        final String app = "APP";
        final String fingerprint = "FP";
        when(req.getParameter("_app")).thenReturn(app);
        when(req.getParameter("_continue")).thenReturn(path);
        when(req.getParameter("_fingerprint")).thenReturn(fingerprint);
        ArgumentCaptor<String> redirectURLCapture = ArgumentCaptor.forClass(String.class);

        successHandler.onAuthenticationSuccess(req, resp, authentication);

        verify(jwtService).authenticateWithJWT(req, resp, authentication, fingerprint);
        verify(jwtService).authenticateWithJWT(req, authentication, app);
        verify(resp).sendRedirect(redirectURLCapture.capture());
        String redirectURL = redirectURLCapture.getValue();
        assertThat(redirectURL)
                .contains("token=")
                .contains("serverTime=");
    }

    static List<String> getInvalidUrls() {
        List<String> decoded = List.of(
                "not_valid_uri",
                "http:://exceed-sign.net",
                "\\another-invalid-uri"
        );
        return decoded.stream()
                .map(s -> new String(Base64.getUrlEncoder().encode(s.getBytes())))
                .toList();
    }

    static List<String> getValidUrls() {
        List<String> decoded = List.of(
                "http://somesite.ru",
                "https://some-secured-site.com"
        );
        return decoded.stream()
                .map(s -> new String(Base64.getUrlEncoder().encode(s.getBytes())))
                .toList();
    }
}