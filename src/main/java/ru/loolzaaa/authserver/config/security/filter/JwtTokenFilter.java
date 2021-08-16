package ru.loolzaaa.authserver.config.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final String refreshTokenURI;

    private final SecurityContextService securityContextService;

    private final JWTService jwtService;
    private final CookieService cookieService;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
                                    FilterChain chain) throws ServletException, IOException {
        String accessToken = cookieService.getCookieValueByName("_t_access", req.getCookies());
        String refreshToken = cookieService.getCookieValueByName("_t_refresh", req.getCookies());

        if (accessToken == null) {
            logger.trace("Access token is null");

            chain.doFilter(req, resp);
            return;
        }

        String login = jwtService.checkAccessToken(accessToken);
        if (login != null) {
            logger.debug(String.format("Access token for user [%s] validated. Update SecurityContext", login));

            securityContextService.updateSecurityContextHolder(req, resp, login);
        } else {
            logger.debug("Invalid access token, try to refresh it");

            if (refreshToken == null) {
                logger.trace("Refresh token is null. Clear SecurityContext");

                securityContextService.clearSecurityContextHolder(req, resp);
                chain.doFilter(req, resp);
                return;
            }

            if (req.getParameter("_fingerprint") == null) {
                logger.trace("There is no fingerprint in request, redirecting to " + refreshTokenURI);

                String continuePath = req.getParameter("_continue");
                if (continuePath == null) {
                    resp.sendRedirect(refreshTokenURI);
                } else {
                    String continueUri = new String(Base64.getUrlDecoder().decode(continuePath));
                    if (StringUtils.hasText(continueUri) && UrlUtils.isValidRedirectUrl(continueUri)) {
                        String redirectURL = UriComponentsBuilder.fromHttpUrl(refreshTokenURI)
                                .queryParam("continue", continueUri)
                                .toUriString();
                        resp.sendRedirect(redirectURL);
                    } else {
                        resp.sendRedirect(refreshTokenURI);
                    }
                }
                return;
            }

            JWTAuthentication jwtAuthentication = jwtService.refreshAccessToken(req, resp, refreshToken);
            if (jwtAuthentication != null) {
                login = jwtAuthentication.getUsername();
                logger.debug(String.format("Refresh token for user [%s] validated and updated. Update SecurityContext", login));

                securityContextService.updateSecurityContextHolder(req, resp, login);
            } else {
                logger.debug("Invalid refresh token. Clear SecurityContext");

                securityContextService.clearSecurityContextHolder(req, resp);
            }
        }
        chain.doFilter(req, resp);
    }
}
