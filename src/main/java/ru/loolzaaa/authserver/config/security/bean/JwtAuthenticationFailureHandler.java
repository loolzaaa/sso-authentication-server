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

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final SsoServerProperties ssoServerProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException ex)
            throws IOException, ServletException {
        String defaultFailureUrl = ssoServerProperties.getLoginPage() + "?credentialsError";

        String continuePath = req.getParameter("_continue");
        if (continuePath != null) {
            defaultFailureUrl += "&continue=" + continuePath;
        }

        setDefaultFailureUrl(defaultFailureUrl);
        super.onAuthenticationFailure(req, resp, ex);
    }
}
