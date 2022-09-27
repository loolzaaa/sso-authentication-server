package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import ru.loolzaaa.authserver.services.LogoutService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtLogoutHandlerTest {

    @Mock
    LogoutService logoutService;

    @Mock
    Authentication authentication;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;

    JwtLogoutHandler jwtLogoutHandler;

    @BeforeEach
    void setUp() {
        jwtLogoutHandler = new JwtLogoutHandler(logoutService);
    }

    @Test
    void shouldInvokeLogoutService() {
        doNothing().when(logoutService).logout(any());

        jwtLogoutHandler.logout(req, resp, authentication);

        verify(logoutService).logout(any());
        verifyNoMoreInteractions(logoutService);
    }
}