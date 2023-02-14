package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final SsoServerProperties ssoServerProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException ex)
            throws IOException, ServletException {
        String exMessage = URLEncoder.encode(ex.getLocalizedMessage(), StandardCharsets.UTF_8);
        String defaultFailureUrl = ssoServerProperties.getLoginPage() + "?credentialsError=" + exMessage;

        String appParameter = req.getParameter("_app");
        String continuePath = req.getParameter("_continue");
        if (appParameter != null && continuePath != null) {
            defaultFailureUrl += "&app=" + appParameter + "&continue=" + continuePath;
        }
        logger.info("Authentication failure. Message: " + ex.getMessage());
        logger.info("Authentication failure. Redirect to: " + continuePath);

        setAllowSessionCreation(false);
        setDefaultFailureUrl(defaultFailureUrl);
        super.onAuthenticationFailure(req, resp, ex);
    }
}
