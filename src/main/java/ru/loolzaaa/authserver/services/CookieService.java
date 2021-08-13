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
        resp.addCookie(createCookie("_t_access", accessToken));
        resp.addCookie(createCookie("_t_refresh", refreshToken));
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

    //TODO: Check path of new cookie. Must work on origin application AND authentication server
    // Now work if all applications on localhost
    public Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        //cookie.setSecure(true); //FIXME: Check it
        cookie.setPath("/");
        return cookie;
    }
}
