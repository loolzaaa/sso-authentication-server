package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final JWTService jwtService;
    private final CookieService cookieService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication)
            throws IOException, ServletException {
        jwtService.authenticateWithJWT(req, resp, authentication);

        String continuePath = cookieService.getCookieValueByName("_continue", req.getCookies());
        if (continuePath == null) {
            super.onAuthenticationSuccess(req, resp, authentication);
        } else {
            cookieService.clearCookieByName(req, resp, "_continue");
            resp.sendRedirect(continuePath);
        }
    }
}
