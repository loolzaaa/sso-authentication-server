package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.services.JWTService;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final JWTService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication)
            throws IOException, ServletException {
        String appParameter = req.getParameter("_app");
        String continueParameter = req.getParameter("_continue");
        String fingerprintParameter = req.getParameter("_fingerprint");

        jwtService.authenticateWithJWT(req, resp, authentication, fingerprintParameter);

        if (appParameter == null || continueParameter == null) {
            logger.info("Authentication success. Redirect to SSO main page.");
            super.onAuthenticationSuccess(req, resp, authentication);
        } else {
            String appName;
            String continueUri;
            try {
                appName = URLDecoder.decode(appParameter, StandardCharsets.UTF_8);
                continueUri = new String(Base64.getUrlDecoder().decode(continueParameter)).replaceAll("[\r\n]", "_");
                if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                    authenticateAndRedirect(req, resp, authentication, appName, continueUri);
                } else {
                    logger.warn("Authentication success. Redirect to SSO main page, " +
                            "because of continue parameter is empty or not absolute url");
                    super.onAuthenticationSuccess(req, resp, authentication);
                }
            } catch (IllegalArgumentException e) {
                logger.warn("Authentication success. Redirect to SSO main page, " +
                        "because of continue parameter is invalid Base64 scheme");
                super.onAuthenticationSuccess(req, resp, authentication);
            }
        }
    }

    private void authenticateAndRedirect(HttpServletRequest req, HttpServletResponse resp, Authentication authentication,
                                         String appName, String continueUri) throws IOException {
        try {
            String accessToken = jwtService.authenticateWithJWT(req, authentication, appName);
            String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUri)
                    .queryParam("token", accessToken)
                    .queryParam("serverTime", System.currentTimeMillis())
                    .toUriString();
            logger.info("Authentication success. Redirect to: " + continueUri);
            resp.sendRedirect(redirectURL);
        } catch (IllegalArgumentException e) {
            throw new InsufficientAuthenticationException(e.getLocalizedMessage());
        }
    }
}
