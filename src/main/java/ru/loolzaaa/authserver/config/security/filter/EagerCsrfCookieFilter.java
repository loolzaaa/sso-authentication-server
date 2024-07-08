package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class EagerCsrfCookieFilter extends OncePerRequestFilter {

    private static final String XSRF_TOKEN_COOKIE_NAME = "XSRF-TOKEN-ENC";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
        // Render the token value to a cookie by causing the deferred token to be loaded
        String tokenValue = csrfToken.getToken();

        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(XSRF_TOKEN_COOKIE_NAME, tokenValue)
                .secure(request.isSecure())
                .path(this.getRequestContext(request))
                .maxAge(-1)
                .httpOnly(false);

        response.addHeader(HttpHeaders.SET_COOKIE, cookieBuilder.build().toString());

        filterChain.doFilter(request, response);
    }

    private String getRequestContext(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (!contextPath.isEmpty()) ? contextPath : "/";
    }
}
