package ru.loolzaaa.authserver.config.security.filter;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class ContinueParameterLoginFilter extends GenericFilterBean {

    private String loginFormUrl;

    public ContinueParameterLoginFilter(String loginFormUrl) {
        this.loginFormUrl = loginFormUrl;
    }

    @Override
    protected void initFilterBean() {
        Assert.isTrue(StringUtils.hasText(this.loginFormUrl) && UrlUtils.isValidRedirectUrl(this.loginFormUrl),
                "loginFormUrl must be specified and must be a valid redirect URL");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) req;

        String continueParameter = req.getParameter("continue");
        if (continueParameter != null) {
            if (!isAuthenticated() && !loginFormUrl.equals(servletRequest.getRequestURI())) {
                //TODO: add parameter check (absolute URL),
                // add context path checks,
                RequestDispatcher dispatcher = req.getRequestDispatcher(loginFormUrl);
                dispatcher.forward(req, resp);
                return;
            }
        }
        chain.doFilter(req, resp);
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || AnonymousAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            return false;
        } else {
            return authentication.isAuthenticated();
        }
    }
}
