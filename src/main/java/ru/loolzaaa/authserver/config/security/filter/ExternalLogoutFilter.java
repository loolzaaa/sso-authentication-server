package ru.loolzaaa.authserver.config.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@RequiredArgsConstructor
public class ExternalLogoutFilter extends OncePerRequestFilter {

    private final SecurityContextService securityContextService;

    private final JWTService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
                                    FilterChain chain) throws ServletException, IOException {
        AntPathRequestMatcher externalLogoutRequestMatcher = new AntPathRequestMatcher("/api/logout");
        RequestMatcher.MatchResult matcher = externalLogoutRequestMatcher.matcher(req);
        if (matcher.isMatch()) {
            String token = req.getParameter("token");
            if (token != null && jwtService.checkTokenForRevoke(token)) {
                securityContextService.clearSecurityContextHolder(req, resp);

                String continuePath = req.getParameter("continue");
                if (continuePath != null) {
                    try {
                        String continueUri = new String(Base64.getUrlDecoder().decode(continuePath));
                        if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                            logger.info("External logout. Redirect to: " + continueUri);
                            resp.sendRedirect(continueUri);
                        }
                    } catch (Exception ignored) {
                        logger.warn("Continue parameter is not valid Base64 scheme: " + continuePath);
                    }
                } else {
                    logger.debug("Continue parameter is null");
                }
                return;
            } else {
                logger.debug("Token is null or not revoked");
            }
        } else {
            logger.trace("Request pattern is not match: " + req.getRequestURI());
        }
        chain.doFilter(req, resp);
    }
}
