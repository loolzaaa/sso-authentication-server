package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.config.WebConfig;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RequiredArgsConstructor
public class LoginAccessFilter extends OncePerRequestFilter {

    private final SsoServerProperties ssoServerProperties;

    private final AccessDeniedHandler accessDeniedHandler;

    private final CookieService cookieService;

    private final JWTService jwtService;

    @Override
    protected void initFilterBean() {
        Assert.isTrue(StringUtils.hasText(this.ssoServerProperties.getLoginPage())
                        && UrlUtils.isValidRedirectUrl(this.ssoServerProperties.getLoginPage()),
                "loginFormUrl must be specified and must be a valid redirect URL");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest servletRequest, HttpServletResponse servletResponse, FilterChain chain)
            throws ServletException, IOException {
        String uriWithoutContextPath = servletRequest.getRequestURI().substring(servletRequest.getContextPath().length());
        String appParameter = servletRequest.getParameter("app");
        String continueParameter = servletRequest.getParameter("continue");
        if (isAuthenticatedUserGoesToLoginPage(uriWithoutContextPath)) {
            logger.debug("Already authenticated user with login path detected");
            // Set already authenticated attribute for late controller processing
            servletRequest.setAttribute(WebConfig.ALREADY_LOGGED_IN_ATTRIBUTE, Boolean.TRUE);

            String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), servletRequest.getCookies());
            if (appParameter == null || continueParameter == null || accessToken == null) {
                logger.debug("Application, continue parameter or access token is null");
                // Redirect to main page in controller function
                chain.doFilter(servletRequest, servletResponse);
                return;
            }

            logger.debug("Suppose application doesn't have access token, but server has");
            try {
                String appName = URLDecoder.decode(appParameter, StandardCharsets.UTF_8);
                String continueUrl = new String(Base64.getUrlDecoder().decode(continueParameter)).replaceAll("[\r\n]", "_");
                logger.debug("Try to redirect to " + continueUrl);
                if (isValidUrl(continueUrl)) {
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    authenticateAndRedirect(servletRequest, servletResponse, authentication, appName, continueUrl);
                    return;
                }
                logger.warn("Continue parameter is not absolute url or empty: " + continueUrl);
                // Redirect to main page in controller function
            } catch (IllegalArgumentException e) {
                logger.warn("Continue parameter is not valid Base64 scheme");
                // Redirect to main page in controller function
            }
        } else if (isNotAuthenticatedUserGoesToLoginPage(uriWithoutContextPath)) {
            if (appParameter == null || continueParameter == null) {
                logger.debug("Application or continue parameter is null");

                chain.doFilter(servletRequest, servletResponse);
                return;
            }

            try {
                String continueUrl = new String(Base64.getUrlDecoder().decode(continueParameter)).replaceAll("[\r\n]", "_");
                if (isValidUrl(continueUrl)) {
                    RequestDispatcher dispatcher = servletRequest.getRequestDispatcher(ssoServerProperties.getLoginPage());
                    dispatcher.forward(servletRequest, servletResponse);
                    return;
                }
                logger.warn("Continue parameter is not absolute url or empty: " + continueUrl);
            } catch (Exception e) {
                logger.warn("Continue parameter is not valid Base64 scheme");
            }
        }
        chain.doFilter(servletRequest, servletResponse);
    }

    private void authenticateAndRedirect(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                         Authentication authentication, String appName, String continueUri) throws IOException, ServletException {
        try {
            String accessToken = jwtService.authenticateWithJWT(servletRequest, authentication, appName);
            String redirectURL = UriComponentsBuilder.fromUriString(continueUri)
                    .queryParam("token", accessToken)
                    .queryParam("serverTime", System.currentTimeMillis())
                    .toUriString();
            servletResponse.sendRedirect(redirectURL);
        } catch (IllegalArgumentException e) {
            accessDeniedHandler.handle(servletRequest, servletResponse, new AccessDeniedException(e.getLocalizedMessage()));
        }
    }

    private boolean isAuthenticatedUserGoesToLoginPage(String uriWithoutContextPath) {
        return isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath);
    }

    private boolean isNotAuthenticatedUserGoesToLoginPage(String uriWithoutContextPath) {
        return !isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath);
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || AnonymousAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            return false;
        }
        return authentication.isAuthenticated();
    }

    private boolean isValidUrl(String url) {
        return StringUtils.hasText(url) && UrlUtils.isAbsoluteUrl(url);
    }
}
