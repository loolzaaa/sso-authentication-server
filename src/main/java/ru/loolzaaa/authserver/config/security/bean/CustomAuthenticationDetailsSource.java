package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;

public class CustomAuthenticationDetailsSource
        implements AuthenticationDetailsSource<HttpServletRequest, AuthenticationDetails> {
    @Override
    public AuthenticationDetails buildDetails(HttpServletRequest context) {
        return new AuthenticationDetails(context);
    }
}
