package ru.loolzaaa.authserver.config.security.bean;

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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationSuccessHandlerTest {

    final String TOKEN = "TOKEN";

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

        when(jwtService.authenticateWithJWT(req, resp, authentication)).thenReturn(TOKEN);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".invalid-base64-string-because-of-start-dot"})
    void shouldUseSuperClassMethodWhenContinuePathIsNullOrNotBase64(String path) throws Exception {
        if ("".equals(path)) path = null;
        when(req.getParameter("_continue")).thenReturn(path);

        successHandler.onAuthenticationSuccess(req, resp, authentication);
    }

    @ParameterizedTest
    @MethodSource("getInvalidUrls")
    void shouldUseSuperClassMethodWhenContinuePathIsEmptyOrInvalid(String path) throws Exception {
        when(req.getParameter("_continue")).thenReturn(path);

        successHandler.onAuthenticationSuccess(req, resp, authentication);
    }

    @ParameterizedTest
    @MethodSource("getValidUrls")
    void shouldRedirectWhenContinuePathIsValid(String path) throws Exception {
        when(req.getParameter("_continue")).thenReturn(path);
        ArgumentCaptor<String> redirectURLCapture = ArgumentCaptor.forClass(String.class);

        successHandler.onAuthenticationSuccess(req, resp, authentication);

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
                .collect(Collectors.toList());
    }

    static List<String> getValidUrls() {
        List<String> decoded = List.of(
                "http://somesite.ru",
                "https://some-secured-site.com"
        );
        return decoded.stream()
                .map(s -> new String(Base64.getUrlEncoder().encode(s.getBytes())))
                .collect(Collectors.toList());
    }
}