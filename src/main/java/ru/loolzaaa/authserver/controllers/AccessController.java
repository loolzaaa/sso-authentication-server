package ru.loolzaaa.authserver.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.dto.RequestStatus;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

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

    private final JWTService jwtService;
    private final CookieService cookieService;

    @PostMapping("/refresh")
    String refreshToken(HttpServletRequest req, HttpServletResponse resp) {
        boolean isRefreshTokenValid = true;

        String refreshToken = cookieService.getCookieValueByName("_t_refresh", req.getCookies());
        if (refreshToken == null) {
            isRefreshTokenValid = false;
            securityContextService.clearSecurityContextHolder(req, resp);
        }

        JWTAuthentication jwtAuthentication = null;
        if (isRefreshTokenValid) {
            jwtAuthentication = jwtService.refreshAccessToken(req, resp, refreshToken);
            if (jwtAuthentication == null) {
                isRefreshTokenValid = false;
                securityContextService.clearSecurityContextHolder(req, resp);
            }
        }

        String continuePath = req.getParameter("_continue");
        if (continuePath == null) {
            return !isRefreshTokenValid ? ("redirect:" + mainLoginPage) : "redirect:/";
        } else {
            String continueUri = new String(Base64.getUrlDecoder().decode(continuePath));
            if (StringUtils.hasText(continueUri) && UrlUtils.isValidRedirectUrl(continueUri)) {
                UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(continueUri);
                if (isRefreshTokenValid) {
                    uriComponentsBuilder
                            .queryParam("token", jwtAuthentication.getAccessToken())
                            .queryParam("serverTime", System.currentTimeMillis());
                }
                return "redirect:" + uriComponentsBuilder.toUriString();
            } else {
                return !isRefreshTokenValid ? ("redirect:" + mainLoginPage) : "redirect:/";
            }
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

        JWTAuthentication jwtAuthentication = jwtService.refreshAccessToken(req, resp, refreshToken);
        if (jwtAuthentication == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RequestStatusDTO.builder()
                            .status(RequestStatus.ERROR)
                            .statusCode(HttpStatus.UNAUTHORIZED)
                            .text("Refresh token is invalid")
                            .build()
                    );
        }

        return ResponseEntity.ok().body(RequestStatusDTO.ok("{\"token\":\"%s\",\"serverTime\":%d}",
                jwtAuthentication.getAccessToken(), System.currentTimeMillis()));
    }

    @PostMapping("/fast/rfid")
    String rfidAuth(HttpServletRequest req, HttpServletResponse resp) {
        if (!rfidActive) throw new AccessDeniedException("RFID authentication disabled");
        if (!StringUtils.hasText(KEY)) throw new AccessDeniedException("There is no valid RFID key for authentication");

        String login = req.getParameter("login");
        String password = req.getParameter("password");
        String from = req.getParameter("from");

        if (!KEY.equals(password)) throw new AccessDeniedException("Incorrect RFID key");

        String continueUri;
        try {
            continueUri = new String(Base64.getUrlDecoder().decode(from));
        } catch (IllegalArgumentException e) {
            throw new RequestErrorException("Invalid Base64 scheme for FROM parameter for RFID authentication");
        }
        if (StringUtils.hasText(continueUri) && UrlUtils.isValidRedirectUrl(continueUri)) {
            securityContextService.updateSecurityContextHolder(req, resp, login);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String accessToken = jwtService.authenticateWithJWT(req, resp, authentication, "RFID");
            //FIXME: need httpOnly = false, for different views in applications
            //TODO: use cookieService
            //resp.addCookie(cookieService.createCookie("_t_rfid", "", req, resp));

            String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUri)
                    .queryParam("token", accessToken)
                    .queryParam("serverTime", System.currentTimeMillis())
                    .toUriString();
            return "redirect:" + redirectURL;
        } else {
            throw new RequestErrorException("Invalid FROM parameter for RFID authentication");
        }
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PostMapping("/fast/prepare_logout")
    void prepareLogout(@RequestHeader("Revoke-Token") String token) {
        jwtService.revokeToken(token);
    }

    public String getKEY() {
        return KEY;
    }

    public void setKEY(String KEY) {
        this.KEY = KEY;
    }
}
