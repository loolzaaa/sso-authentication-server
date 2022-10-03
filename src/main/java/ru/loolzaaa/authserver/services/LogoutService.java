package ru.loolzaaa.authserver.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.loolzaaa.authserver.config.security.CookieName;

import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
@Service
public class LogoutService {

    private final JWTService jwtService;
    private final CookieService cookieService;

    public void logout(HttpServletRequest req) {
        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());
        if (refreshToken != null) {
            jwtService.deleteTokenFromDatabase(refreshToken);
        }
    }
}
