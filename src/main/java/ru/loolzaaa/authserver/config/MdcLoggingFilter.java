package ru.loolzaaa.authserver.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Populates {@link MDC} with request scoped diagnostics
 * ({@code requestId}, {@code clientIp}) so that every log line
 * can be correlated with a request, and clears all MDC fields
 * once the request is finished.
 * <p>
 * The {@code username} field is intentionally not resolved here:
 * this filter runs before the Spring Security filter chain, when
 * the authentication is not established yet. It is populated by
 * {@link MdcUsernameFilter} after authentication and by
 * {@link ru.loolzaaa.authserver.services.SecurityContextService}.
 */
public class MdcLoggingFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID = "requestId";
    public static final String CLIENT_IP = "clientIp";
    public static final String USERNAME = "username";

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
            throws ServletException, IOException {
        try {
            MDC.put(REQUEST_ID, UUID.randomUUID().toString().substring(0, 8));
            MDC.put(CLIENT_IP, resolveClientIp(req));
            chain.doFilter(req, resp);
        } finally {
            MDC.remove(REQUEST_ID);
            MDC.remove(CLIENT_IP);
            MDC.remove(USERNAME);
        }
    }

    private String resolveClientIp(HttpServletRequest req) {
        String forwardedFor = req.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwardedFor)) {
            int commaIndex = forwardedFor.indexOf(',');
            return commaIndex > 0 ? forwardedFor.substring(0, commaIndex).trim() : forwardedFor.trim();
        }
        return req.getRemoteAddr();
    }
}
