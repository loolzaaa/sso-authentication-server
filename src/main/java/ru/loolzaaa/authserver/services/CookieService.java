package ru.loolzaaa.authserver.services;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.util.Arrays;
import java.util.Collection;

@RequiredArgsConstructor
@Service
public class CookieService {

    private final SsoServerProperties ssoServerProperties;

    public String getCookieValueByName(String cookieName, Cookie[] cookies) {
        if (cookieName == null) {
            throw new NullPointerException("Cookie name must not be null");
        }
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (cookieName.equals(c.getName())) {
                    return c.getValue();
                }
            }
        }
        return null;
    }

    public void updateTokenCookies(HttpServletRequest req, HttpServletResponse resp,
                                   String accessToken, String refreshToken, boolean isRfid) {
        resp.addCookie(createCookie(CookieName.ACCESS.getName(), accessToken, req));
        resp.addCookie(createCookie(CookieName.REFRESH.getName(), refreshToken, req));
        if (isRfid) {
            resp.addCookie(createCookie(CookieName.RFID.getName(), "", req));
        }

        addSameSiteAttributeToAllCookies(resp);
    }

    public void clearCookies(HttpServletRequest req, HttpServletResponse resp) {
        if (req.getCookies() == null) return;
        Arrays.stream(req.getCookies()).forEach(cookie -> clearCookieByName(req, resp, cookie.getName()));
        addSameSiteAttributeToAllCookies(resp);
    }

    public void clearCookieByName(HttpServletRequest req, HttpServletResponse resp, String name) {
        Cookie c = new Cookie(name, null);
        c.setHttpOnly(true);
        c.setSecure(req.isSecure());
        c.setPath(getRequestContext(req));
        c.setMaxAge(0);
        resp.addCookie(c);
    }

    // This method used only for passport cookie creation
    public Cookie createCookie(String name, String value, HttpServletRequest req) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(req.isSecure());
        cookie.setPath(getRequestContext(req));
        return cookie;
    }

    private void addSameSiteAttributeToAllCookies(HttpServletResponse resp) {
        Collection<String> headers = resp.getHeaders(HttpHeaders.SET_COOKIE);
        boolean firstHeader = true;
        for (String header : headers) {
            final String COOKIE_NAME_PATTERN = String.format(".*%s.*|.*%s.*|.*%s.*",
                    CookieName.ACCESS.getName(), CookieName.REFRESH.getName(), CookieName.RFID.getName());
            if (firstHeader) {
                if (header.matches(COOKIE_NAME_PATTERN)) {
                    resp.setHeader(HttpHeaders.SET_COOKIE, String.format(
                            "%s; SameSite=%s", header, ssoServerProperties.getCookie().getSameSite()));
                } else {
                    resp.setHeader(HttpHeaders.SET_COOKIE, header);
                }
                firstHeader = false;
                continue;
            }
            if (header.matches(COOKIE_NAME_PATTERN)) {
                resp.addHeader(HttpHeaders.SET_COOKIE, String.format(
                        "%s; SameSite=%s", header, ssoServerProperties.getCookie().getSameSite()));
            } else {
                resp.addHeader(HttpHeaders.SET_COOKIE, header);
            }
        }
    }

    private String getRequestContext(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (!contextPath.isEmpty()) ? contextPath : "/";
    }
}
