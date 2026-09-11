package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.audit.AuditLogger;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
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
        log.warn("Authentication failure: {}", AuditLogger.sanitize(ex.getLocalizedMessage()));
        AuditLogger.loginFailure(req.getParameter("username"), req.getRemoteAddr(), ex.getLocalizedMessage());

        setAllowSessionCreation(false);
        setDefaultFailureUrl(defaultFailureUrl);
        super.onAuthenticationFailure(req, resp, ex);
    }
}
