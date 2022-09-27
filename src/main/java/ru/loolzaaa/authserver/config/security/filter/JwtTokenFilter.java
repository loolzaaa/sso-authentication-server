package ru.loolzaaa.authserver.config.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.bean.IgnoredPathsHandler;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final SsoServerProperties ssoServerProperties;

    private final IgnoredPathsHandler ignoredPathsHandler;

    private final SecurityContextService securityContextService;

    private final JWTService jwtService;
    private final CookieService cookieService;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
                                    FilterChain chain) throws ServletException, IOException {
        String requestedUri = req.getRequestURI().substring(req.getContextPath().length());
        if (ignoredPathsHandler.checkUri(requestedUri)) {
            logger.debug(String.format("Access to '%s' is permitted without jwt filter", requestedUri));

            chain.doFilter(req, resp);
            return;
        }

        String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), req.getCookies());
        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());

        if (accessToken == null) {
            logger.trace("Access token is null");

            chain.doFilter(req, resp);
            return;
        }

        String login = jwtService.checkAccessToken(accessToken);
        if (login != null) {
            logger.debug(String.format("Access token for user [%s] validated. Update SecurityContext", login));

            securityContextService.updateSecurityContextHolder(req, login);
        } else {
            logger.debug("Invalid access token, try to refresh it");

            if (refreshToken == null) {
                logger.trace("Refresh token is null. Clear SecurityContext");

                securityContextService.clearSecurityContextHolder(req, resp);
                chain.doFilter(req, resp);
                return;
            }

            if (req.getParameter("_fingerprint") == null) {
                String acceptHeader = req.getHeader("Accept");
                if (acceptHeader != null && acceptHeader.toLowerCase().contains("application/json")) {
                    logger.debug("Ajax request detected. Refresh via Auth Server API");

                    String fingerprintRequestUrl = getServerUrl(req) + "/api/refresh/ajax";
                    resp.setHeader("fp_request", fingerprintRequestUrl);
                    resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                } else {
                    logger.debug("Browser request detected. Refresh via redirect to " + ssoServerProperties.getRefreshUri());

                    // If client application NOT CONTAIN access token, it will redirect to login with continue param,
                    // but SSO application can contain access token, so it will try to refresh it
                    String continuePath = req.getParameter("continue");
                    if (continuePath == null) {
                        resp.sendRedirect(req.getContextPath() + ssoServerProperties.getRefreshUri());
                    } else {
                        String redirectURL = UriComponentsBuilder.fromHttpUrl(getServerUrl(req) + ssoServerProperties.getRefreshUri())
                                .queryParam("continue", continuePath)
                                .toUriString();
                        resp.sendRedirect(redirectURL);
                    }
                }
                return;
            }

            JWTAuthentication jwtAuthentication = jwtService.refreshAccessToken(req, resp, refreshToken);
            if (jwtAuthentication != null) {
                login = jwtAuthentication.getUsername();
                logger.debug(String.format("Refresh token for user [%s] validated and updated. Update SecurityContext", login));

                securityContextService.updateSecurityContextHolder(req, login);
            } else {
                logger.debug("Invalid refresh token. Clear SecurityContext");

                securityContextService.clearSecurityContextHolder(req, resp);
            }
        }
        chain.doFilter(req, resp);
    }

    private String getServerUrl(HttpServletRequest req) {
        String fullRequestUrl = UrlUtils.buildFullRequestUrl(req);
        String requestUrl = fullRequestUrl.substring(0, fullRequestUrl.indexOf(req.getRequestURI()));
        return requestUrl + req.getContextPath();
    }
}
