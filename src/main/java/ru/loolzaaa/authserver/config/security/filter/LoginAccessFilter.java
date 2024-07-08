package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
        if (isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath)) {
            logger.debug("Already authenticated user with login path detected");

            String appParameter = req.getParameter("app");
            String continueParameter = req.getParameter("continue");
            String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), servletRequest.getCookies());
            if (appParameter != null && continueParameter != null && accessToken != null) {
                logger.debug("Suppose application doesn't have access token, but server has");
                String appName;
                String continueUri;
                try {
                    appName = URLDecoder.decode(appParameter, StandardCharsets.UTF_8);
                    continueUri = new String(Base64.getUrlDecoder().decode(continueParameter));
                    logger.debug("Try to redirect to " + continueUri);
                    if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                        try {
                            accessToken = jwtService.authenticateWithJWT(servletRequest, authentication, appName);
                            String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUri)
                                    .queryParam("token", accessToken)
                                    .queryParam("serverTime", System.currentTimeMillis())
                                    .toUriString();
                            servletResponse.sendRedirect(redirectURL);
                            return;
                        } catch (IllegalArgumentException e) {
                            accessDeniedHandler.handle(servletRequest, servletResponse, new AccessDeniedException(e.getLocalizedMessage()));
                            return;
                        }
                    } else {
                        logger.warn("Continue parameter is not absolute url or empty: " + continueParameter);
                        String encodedRedirectURL = servletResponse.encodeRedirectURL(servletRequest.getContextPath() + "/");

                        servletResponse.setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
                        servletResponse.setHeader("Location", encodedRedirectURL);
                    }
                } catch (IllegalArgumentException e) {
                    logger.warn("Continue parameter is not valid Base64 scheme: " + continueParameter);
                    String encodedRedirectURL = servletResponse.encodeRedirectURL(servletRequest.getContextPath() + "/");

                    servletResponse.setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
                    servletResponse.setHeader("Location", encodedRedirectURL);
                }
            } else {
                logger.debug("Continue parameter or access token is null");
                String encodedRedirectURL = servletResponse.encodeRedirectURL(servletRequest.getContextPath() + "/");

                servletResponse.setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
                servletResponse.setHeader("Location", encodedRedirectURL);
            }
        } else if (!isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath)) {
            String appParameter = req.getParameter("app");
            String continueParameter = req.getParameter("continue");
            if (appParameter != null && continueParameter != null) {
                String continueUri;
                try {
                    continueUri = new String(Base64.getUrlDecoder().decode(continueParameter));
                    if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                        RequestDispatcher dispatcher = req.getRequestDispatcher(ssoServerProperties.getLoginPage());
                        dispatcher.forward(req, resp);
                        return;
                    } else {
                        logger.warn("Continue parameter is not absolute url or empty: " + continueParameter);
                    }
                } catch (Exception e) {
                    logger.warn("Continue parameter is not valid Base64 scheme: " + continueParameter);
                }
            }
        }
        chain.doFilter(servletRequest, servletResponse);
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || AnonymousAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            return false;
        }
        return authentication.isAuthenticated();
    }
}
