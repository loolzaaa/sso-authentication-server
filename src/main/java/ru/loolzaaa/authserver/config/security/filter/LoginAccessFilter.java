package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RequiredArgsConstructor
public class LoginAccessFilter extends GenericFilterBean {

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
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) req;
        HttpServletResponse servletResponse = (HttpServletResponse) resp;

        String uriWithoutContextPath = servletRequest.getRequestURI().substring(servletRequest.getContextPath().length());
        String appParameter = req.getParameter("app");
        String continueParameter = req.getParameter("continue");
        if (isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath)) {
            logger.debug("Already authenticated user with login path detected");

            String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), servletRequest.getCookies());
            if (appParameter == null || continueParameter == null || accessToken == null) {
                logger.debug("Continue parameter or access token is null");
                setTemporaryRedirect(servletRequest, servletResponse);

                chain.doFilter(servletRequest, servletResponse);
                return;
            }

            logger.debug("Suppose application doesn't have access token, but server has");
            String appName;
            String continueUri;
            try {
                appName = URLDecoder.decode(appParameter, StandardCharsets.UTF_8);
                continueUri = new String(Base64.getUrlDecoder().decode(continueParameter)).replaceAll("[\r\n]", "_");
                logger.debug("Try to redirect to " + continueUri);
                if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    authenticateAndRedirect(servletRequest, servletResponse, authentication, appName, continueUri);
                    return;
                } else {
                    logger.warn("Continue parameter is not absolute url or empty: " + continueUri);
                    setTemporaryRedirect(servletRequest, servletResponse);
                }
            } catch (IllegalArgumentException e) {
                logger.warn("Continue parameter is not valid Base64 scheme");
                setTemporaryRedirect(servletRequest, servletResponse);
            }
        } else if (!isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath)) {
            if (appParameter == null || continueParameter == null) {
                chain.doFilter(servletRequest, servletResponse);
                return;
            }

            String continueUri;
            try {
                continueUri = new String(Base64.getUrlDecoder().decode(continueParameter)).replaceAll("[\r\n]", "_");
                if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                    RequestDispatcher dispatcher = req.getRequestDispatcher(ssoServerProperties.getLoginPage());
                    dispatcher.forward(req, resp);
                    return;
                } else {
                    logger.warn("Continue parameter is not absolute url or empty: " + continueUri);
                }
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
            String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUri)
                    .queryParam("token", accessToken)
                    .queryParam("serverTime", System.currentTimeMillis())
                    .toUriString();
            servletResponse.sendRedirect(redirectURL);
        } catch (IllegalArgumentException e) {
            accessDeniedHandler.handle(servletRequest, servletResponse, new AccessDeniedException(e.getLocalizedMessage()));
        }
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || AnonymousAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            return false;
        }
        return authentication.isAuthenticated();
    }

    private void setTemporaryRedirect(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        String contextPath = servletRequest.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath += "/";
        }
        String encodedRedirectURL = servletResponse.encodeRedirectURL(contextPath);

        servletResponse.setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
        servletResponse.setHeader(HttpHeaders.LOCATION, encodedRedirectURL);
    }
}
