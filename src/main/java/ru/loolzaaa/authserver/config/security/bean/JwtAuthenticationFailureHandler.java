package ru.loolzaaa.authserver.config.security.bean;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${auth.main.login.page}")
    private String mainLoginPage;

    @Override
    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException ex)
            throws IOException, ServletException {
        String defaultFailureUrl = mainLoginPage + "?credentialsError";

        String continuePath = req.getParameter("_continue");
        if (continuePath != null) {
            defaultFailureUrl += "&continue=" + continuePath;
        }

        setDefaultFailureUrl(defaultFailureUrl);
        super.onAuthenticationFailure(req, resp, ex);
    }
}
