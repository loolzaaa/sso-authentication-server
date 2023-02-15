package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtLogoutHandlerTest {

    @Mock
    JWTService jwtService;
    @Mock
    CookieService cookieService;

    @Mock
    Authentication authentication;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;

    JwtLogoutHandler jwtLogoutHandler;

    @BeforeEach
    void setUp() {
        jwtLogoutHandler = new JwtLogoutHandler(jwtService, cookieService);
    }

    @Test
    void shouldNotUserJwtServiceIfRefreshTokenIsNull() {
        when(req.getCookies()).thenReturn(new Cookie[0]);
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(null);

        jwtLogoutHandler.logout(req, resp, authentication);

        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldDeleteTokenFromBase() {
        final String TOKEN = "token";
        when(req.getCookies()).thenReturn(new Cookie[0]);
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(TOKEN);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        jwtLogoutHandler.logout(req, resp, authentication);

        verify(jwtService).deleteTokenFromDatabase(tokenCaptor.capture());
        assertEquals(tokenCaptor.getValue(), TOKEN);
    }
}