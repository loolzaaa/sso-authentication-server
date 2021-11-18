package ru.loolzaaa.authserver.config.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.UrlUtils;
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
        //TODO: AntMatcher create?
        String uriWithoutContextPath = req.getRequestURI().substring(req.getContextPath().length());
        if ("/api/logout".equals(uriWithoutContextPath)) {
            String token = req.getParameter("token");
            if (token != null && jwtService.checkTokenForRevoke(token)) {
                securityContextService.clearSecurityContextHolder(req, resp);

                String continuePath = req.getParameter("continue");
                if (continuePath != null) {
                    try {
                        String continueUri = new String(Base64.getUrlDecoder().decode(continuePath));
                        if (StringUtils.hasText(continueUri) && UrlUtils.isAbsoluteUrl(continueUri)) {
                            resp.sendRedirect(continueUri);
                        }
                    } catch (Exception ignored) {}
                }
                return;
            }
        }
        chain.doFilter(req, resp);
    }
}
