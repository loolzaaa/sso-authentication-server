package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.services.LogoutService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@Component
public class JwtLogoutHandler implements LogoutHandler {

    private final LogoutService logoutService;

    @Override
    public void logout(HttpServletRequest req, HttpServletResponse resp, Authentication auth) {
        logoutService.logout(req, resp);
    }
}
