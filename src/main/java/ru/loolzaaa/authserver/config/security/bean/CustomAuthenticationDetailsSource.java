package ru.loolzaaa.authserver.config.security.bean;

import org.springframework.security.authentication.AuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

public class CustomAuthenticationDetailsSource
        implements AuthenticationDetailsSource<HttpServletRequest, AuthenticationDetails> {
    @Override
    public AuthenticationDetails buildDetails(HttpServletRequest context) {
        return new AuthenticationDetails(context);
    }
}
