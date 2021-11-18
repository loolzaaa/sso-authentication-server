package ru.loolzaaa.authserver.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@Service
public class LogoutService {

    private final JWTService jwtService;
    private final CookieService cookieService;

    public void logout(HttpServletRequest req, HttpServletResponse resp) {
        String refreshToken = cookieService.getCookieValueByName("_t_refresh", req.getCookies());
        if (refreshToken != null) {
            jwtService.deleteTokenFromDatabase(refreshToken);
        }
    }
}
