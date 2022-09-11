package ru.loolzaaa.authserver.config.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class LoginAccessFilter extends GenericFilterBean {

    private final SsoServerProperties ssoServerProperties;

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

            String encodedRedirectURL = servletResponse.encodeRedirectURL(servletRequest.getContextPath() + "/");

            servletResponse.setStatus(HttpStatus.TEMPORARY_REDIRECT.value());
            servletResponse.setHeader("Location", encodedRedirectURL);
        } else if (!isAuthenticated() && ssoServerProperties.getLoginPage().equals(uriWithoutContextPath)) {
            String continueParameter = req.getParameter("continue");
            if (continueParameter != null) {
                //TODO: add parameter check (absolute URL)
                RequestDispatcher dispatcher = req.getRequestDispatcher(ssoServerProperties.getLoginPage());
                dispatcher.forward(req, resp);
                return;
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
