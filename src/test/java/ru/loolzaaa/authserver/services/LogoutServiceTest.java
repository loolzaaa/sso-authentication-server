package ru.loolzaaa.authserver.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LogoutServiceTest {

    @Mock
    JWTService jwtService;
    @Mock
    CookieService cookieService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;

    LogoutService logoutService;

    @BeforeEach
    void setUp() {
        logoutService = new LogoutService(jwtService, cookieService);
    }

    @Test
    void shouldNotUserJwtServiceIfRefreshTokenIsNull() {
        when(req.getCookies()).thenReturn(new Cookie[0]);
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(null);

        logoutService.logout(req, resp);

        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldDeleteTokenFromBase() {
        final String TOKEN = "token";
        when(req.getCookies()).thenReturn(new Cookie[0]);
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(TOKEN);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        logoutService.logout(req, resp);

        verify(jwtService).deleteTokenFromDatabase(tokenCaptor.capture());
        assertEquals(tokenCaptor.getValue(), TOKEN);
    }
}