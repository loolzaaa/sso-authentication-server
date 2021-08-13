package ru.loolzaaa.authserver.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.loolzaaa.authserver.dto.RequestStatus;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.LogoutService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@Controller
@RequestMapping("/api")
public class AccessController {

    private String KEY = "49A9Tr3PAyFHaqM6XfjtUhxm59icL4Ql4xxTvPCqZs2QmNkCEJhkb1j5L9DHZaAA";

    @Value("${auth.main.login.page}")
    private String mainLoginPage;
    @Value("${auth.rfid.activate}")
    private boolean rfidActive;

    private final SecurityContextService securityContextService;

    private final LogoutService logoutService;

    private final JWTService jwtService;
    private final CookieService cookieService;

    @PostMapping("/refresh")
    String refreshToken(HttpServletRequest req, HttpServletResponse resp) {
        String refreshToken = cookieService.getCookieValueByName("_t_refresh", req.getCookies());
        if (refreshToken == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return "redirect:" + mainLoginPage;
        }

        String login = jwtService.refreshAccessToken(req, resp, refreshToken);
        if (login == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return "redirect:" + mainLoginPage;
        }

        String continuePath = cookieService.getCookieValueByName("_continue", req.getCookies());
        if (continuePath == null) {
            return "redirect:/";
        } else {
            cookieService.clearCookieByName(req, resp, "_continue");
            return "redirect:" + continuePath;
        }
    }

    @PostMapping("/refresh/ajax")
    ResponseEntity<RequestStatusDTO> refreshTokenByAjax(HttpServletRequest req, HttpServletResponse resp) {
        String refreshToken = cookieService.getCookieValueByName("_t_refresh", req.getCookies());
        if (refreshToken == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RequestStatusDTO.builder()
                            .status(RequestStatus.ERROR)
                            .statusCode(HttpStatus.UNAUTHORIZED)
                            .text("There is no refresh token")
                            .build()
                    );
        }

        String login = jwtService.refreshAccessToken(req, resp, refreshToken);
        if (login == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RequestStatusDTO.builder()
                            .status(RequestStatus.ERROR)
                            .statusCode(HttpStatus.UNAUTHORIZED)
                            .text("Refresh token is invalid")
                            .build()
                    );
        }

        return ResponseEntity.ok().body(RequestStatusDTO.ok("Token refreshed"));
    }

    @PostMapping("/fast/rfid")
    String rfidAuth(HttpServletRequest req, HttpServletResponse resp) {
        if (!rfidActive) throw new AccessDeniedException("RFID authentication disabled");
        if (!StringUtils.hasText(KEY)) throw new AccessDeniedException("There is no valid RFID key for authentication");

        String login = req.getParameter("login");
        String password = req.getParameter("password");
        String from = req.getParameter("from");

        if (!KEY.equals(password)) throw new AccessDeniedException("Incorrect RFID key");
        if (!StringUtils.hasText(from)) throw new RequestErrorException("In RFID authentication MUST be a FROM parameter in URL");

        securityContextService.updateSecurityContextHolder(req, resp, login);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        jwtService.authenticateWithJWT(req, resp, authentication, "RFID");
        resp.addCookie(cookieService.createCookie("_t_rfid", ""));

        return "redirect:" + from;
    }

    @PostMapping("/fast/logout")
    void logout(HttpServletRequest req, HttpServletResponse resp) {
        logoutService.logout(req, resp);
    }

    public String getKEY() {
        return KEY;
    }

    public void setKEY(String KEY) {
        this.KEY = KEY;
    }
}
