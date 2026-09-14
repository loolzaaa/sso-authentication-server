package ru.loolzaaa.authserver.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Populates the {@code username} {@link MDC} field from the
 * authentication established by the Spring Security filter chain.
 * <p>
 * Registered right after the Spring Security filter (see
 * {@link WebConfig}), so it runs for every security filter chain
 * (JWT, Basic, Actuator) once the user is authenticated. The field
 * is cleared by {@link MdcLoggingFilter} when the request finishes.
 */
public class MdcUsernameFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)
                && StringUtils.hasText(authentication.getName())) {
            MDC.put(MdcLoggingFilter.USERNAME, authentication.getName());
        }
        chain.doFilter(req, resp);
    }
}
