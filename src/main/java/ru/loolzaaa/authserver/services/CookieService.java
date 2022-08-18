package ru.loolzaaa.authserver.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collection;

@Service
public class CookieService {

    private static final String COOKIE_NAME_PATTERN = ".*_t_access.*|.*_t_refresh.*|.*_t_rfid.*";

    @Value("${auth.cookie.same-site}")
    String sameSiteValue;

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

    public void updateTokenCookies(HttpServletRequest req, HttpServletResponse resp, String accessToken, String refreshToken) {
        resp.addCookie(createCookie("_t_access", accessToken, req, resp));
        resp.addCookie(createCookie("_t_refresh", refreshToken, req, resp));

        addSameSiteAttributeToAllCookies(req, resp);
    }

    public void clearCookies(HttpServletRequest req, HttpServletResponse resp) {
        if (req.getCookies() == null) return;
        Arrays.stream(req.getCookies()).forEach(cookie -> {
            clearCookieByName(req, resp, cookie.getName());
        });
        addSameSiteAttributeToAllCookies(req, resp);
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
    public Cookie createCookie(String name, String value, HttpServletRequest req, HttpServletResponse resp) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(req.isSecure());
        cookie.setPath(getRequestContext(req));
        return cookie;
    }

    private void addSameSiteAttributeToAllCookies(HttpServletRequest req, HttpServletResponse resp) {
        Collection<String> headers = resp.getHeaders(HttpHeaders.SET_COOKIE);
        boolean firstHeader = true;
        for (String header : headers) {
            if (firstHeader) {
                if (header.matches(COOKIE_NAME_PATTERN)) {
                    resp.setHeader(HttpHeaders.SET_COOKIE, String.format("%s; SameSite=%s", header, sameSiteValue));
                } else {
                    resp.setHeader(HttpHeaders.SET_COOKIE, header);
                }
                firstHeader = false;
                continue;
            }
            if (header.matches(COOKIE_NAME_PATTERN)) {
                resp.addHeader(HttpHeaders.SET_COOKIE, String.format("%s; SameSite=%s", header, sameSiteValue));
            } else {
                resp.addHeader(HttpHeaders.SET_COOKIE, header);
            }
        }
    }

    private String getRequestContext(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (contextPath.length() > 0) ? contextPath : "/";
    }
}
