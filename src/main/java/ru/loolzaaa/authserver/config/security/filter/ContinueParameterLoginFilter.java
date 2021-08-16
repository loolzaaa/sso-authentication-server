package ru.loolzaaa.authserver.config.security.filter;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
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
        String continueParameter = req.getParameter("continue");
        if (continueParameter != null) {
            //TODO: add parameter check,
            // add context path checks,
            // add SecurityContext checks
            RequestDispatcher dispatcher = req.getRequestDispatcher(loginFormUrl);
            dispatcher.forward(req, resp);
        } else {
            chain.doFilter(req, resp);
        }
    }
}
