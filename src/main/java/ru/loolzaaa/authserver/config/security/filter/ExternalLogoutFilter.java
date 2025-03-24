package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import java.io.IOException;
import java.util.Base64;

@RequiredArgsConstructor
public class ExternalLogoutFilter extends OncePerRequestFilter {

    private final SecurityContextService securityContextService;

    private final JWTService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse resp,
                                    FilterChain chain
    ) throws ServletException, IOException {
        AntPathRequestMatcher externalLogoutRequestMatcher = new AntPathRequestMatcher("/api/logout");
        RequestMatcher.MatchResult matcher = externalLogoutRequestMatcher.matcher(req);
        if (!matcher.isMatch()) {
            logger.trace("Request pattern is not match: " + req.getRequestURI());
            chain.doFilter(req, resp);
            return;
        }

        String token = req.getParameter("token");
        if (isTokenIsNullOrNotRevoked(token)) {
            chain.doFilter(req, resp);
            return;
        }

        securityContextService.clearSecurityContextHolder(req, resp);

        String continuePath = req.getParameter("continue");
        if (continuePath == null) {
            logger.debug("Continue parameter is null");
            return;
        }

        try {
            String continueUri = new String(Base64.getUrlDecoder().decode(continuePath)).replaceAll("[\r\n]", "_");
            if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                logger.info("External logout. Redirect to: " + continueUri);
                resp.sendRedirect(continueUri);
            }
        } catch (Exception ignored) {
            logger.warn("Continue parameter is not valid Base64 scheme");
        }
    }

    private boolean isTokenIsNullOrNotRevoked(String token) {
        boolean tokenIsNullOrNotRevoked = token == null || !jwtService.checkTokenForRevoke(token);
        if (tokenIsNullOrNotRevoked) {
            logger.debug("Token is null or not revoked");
        }
        return tokenIsNullOrNotRevoked;
    }
}
