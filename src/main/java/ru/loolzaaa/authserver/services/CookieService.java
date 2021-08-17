package ru.loolzaaa.authserver.services;

import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;

@Service
public class CookieService {

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
        resp.addCookie(createCookie("_t_access", accessToken, req.isSecure()));
        resp.addCookie(createCookie("_t_refresh", refreshToken, req.isSecure()));
    }

    public void clearCookies(HttpServletRequest req, HttpServletResponse resp) {
        if (req.getCookies() == null) return;
        Arrays.stream(req.getCookies()).forEach(cookie -> {
            clearCookieByName(req, resp, cookie.getName());
        });
    }

    public void clearCookieByName(HttpServletRequest req, HttpServletResponse resp, String name) {
        Cookie c = new Cookie(name, null);
        c.setHttpOnly(true);
        c.setSecure(req.isSecure());
        c.setPath(req.getContextPath() + "/");
        c.setMaxAge(0);
        resp.addCookie(c);
    }

    // This method used only for passport cookie creation
    public Cookie createCookie(String name, String value, boolean secure) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        return cookie;
    }
}
