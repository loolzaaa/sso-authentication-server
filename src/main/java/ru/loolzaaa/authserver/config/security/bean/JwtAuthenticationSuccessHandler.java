package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.services.JWTService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final JWTService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication)
            throws IOException, ServletException {
        String accessToken = jwtService.authenticateWithJWT(req, resp, authentication);

        String continuePath = req.getParameter("_continue");
        if (continuePath == null) {
            super.onAuthenticationSuccess(req, resp, authentication);
        } else {
            String continueUri = new String(Base64.getUrlDecoder().decode(continuePath));
            //TODO absolute/relative URL path check
            //TODO decode token
            String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUri).queryParam("token", accessToken).toUriString();
            resp.sendRedirect(redirectURL);
        }
    }
}
