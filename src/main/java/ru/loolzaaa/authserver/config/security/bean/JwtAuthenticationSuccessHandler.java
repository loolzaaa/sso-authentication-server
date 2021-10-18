package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
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
            String continueUri;
            try {
                continueUri = new String(Base64.getUrlDecoder().decode(continuePath));
                if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                    String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUri)
                            .queryParam("token", accessToken)
                            .queryParam("serverTime", System.currentTimeMillis())
                            .toUriString();
                    resp.sendRedirect(redirectURL);
                } else {
                    super.onAuthenticationSuccess(req, resp, authentication);
                }
            } catch (IllegalArgumentException e) {
                super.onAuthenticationSuccess(req, resp, authentication);
            }
        }
    }
}
