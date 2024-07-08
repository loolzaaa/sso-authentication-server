package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;

@RequiredArgsConstructor
@Component
public class JwtLogoutHandler implements LogoutHandler {

    private final JWTService jwtService;
    private final CookieService cookieService;

    @Override
    public void logout(HttpServletRequest req, HttpServletResponse resp, Authentication auth) {
        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());
        if (refreshToken != null) {
            jwtService.deleteTokenFromDatabase(refreshToken);
        }
    }
}
