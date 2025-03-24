package ru.loolzaaa.authserver.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.dto.RequestStatus;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import java.util.Base64;

@RequiredArgsConstructor
@Controller
@RequestMapping("/api")
public class AccessController {

    private static final String REDIRECT_CMD = "redirect:";

    @Getter
    @Setter
    private String rfidKEY = "49A9Tr3PAyFHaqM6XfjtUhxm59icL4Ql4xxTvPCqZs2QmNkCEJhkb1j5L9DHZaAA";

    private final SsoServerProperties ssoServerProperties;

    private final SecurityContextService securityContextService;

    private final JWTService jwtService;
    private final CookieService cookieService;

    @PostMapping("/refresh")
    String refreshToken(HttpServletRequest req, HttpServletResponse resp) {
        boolean isRefreshTokenValid = true;

        String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), req.getCookies());
        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());
        if (accessToken == null || refreshToken == null) {
            isRefreshTokenValid = false;
            securityContextService.clearSecurityContextHolder(req, resp);
        }

        JWTAuthentication jwtAuthentication = null;
        if (isRefreshTokenValid) {
            try {
                jwtAuthentication = jwtService.refreshAccessToken(req, resp, accessToken, refreshToken);
                if (jwtAuthentication == null) {
                    isRefreshTokenValid = false;
                    securityContextService.clearSecurityContextHolder(req, resp);
                }
            } catch (IllegalArgumentException e) {
                throw new AccessDeniedException(e.getLocalizedMessage());
            }
        }

        String continuePath = req.getParameter("_continue");
        if (continuePath == null) {
            return !isRefreshTokenValid ? (REDIRECT_CMD + ssoServerProperties.getLoginPage()) : REDIRECT_CMD + "/";
        }
        String continueUrl = new String(Base64.getUrlDecoder().decode(continuePath));
        if (!isValidRedirectUrl(continueUrl)) {
            return !isRefreshTokenValid ? (REDIRECT_CMD + ssoServerProperties.getLoginPage()) : REDIRECT_CMD + "/";
        }
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(continueUrl);
        if (isRefreshTokenValid && req.getParameter("_app") != null) {
            uriComponentsBuilder
                    .queryParam("token", jwtAuthentication.getAccessToken())
                    .queryParam("serverTime", System.currentTimeMillis());
        }
        return REDIRECT_CMD + uriComponentsBuilder.toUriString();
    }

    @PostMapping("/refresh/ajax")
    ResponseEntity<RequestStatusDTO> refreshTokenByAjax(HttpServletRequest req, HttpServletResponse resp) {
        String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), req.getCookies());
        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());
        if (accessToken == null || refreshToken == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RequestStatusDTO.builder()
                            .status(RequestStatus.ERROR)
                            .statusCode(HttpStatus.UNAUTHORIZED)
                            .text("There is no refresh token")
                            .build()
                    );
        }

        try {
            JWTAuthentication jwtAuthentication = jwtService.refreshAccessToken(req, resp, accessToken, refreshToken);
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

            String body = String.format("{\"token\":\"%s\",\"serverTime\":%d}",
                    jwtAuthentication.getAccessToken(), System.currentTimeMillis());
            return ResponseEntity.ok().body(RequestStatusDTO.ok(body));
        } catch (IllegalArgumentException e) {
            throw new AccessDeniedException(e.getLocalizedMessage());
        }
    }

    @PostMapping("/fast/rfid")
    String rfidAuth(HttpServletRequest req, HttpServletResponse resp) {
        if (!ssoServerProperties.getRfid().isActivate()) {
            throw new AccessDeniedException("RFID authentication disabled");
        }
        if (!StringUtils.hasText(rfidKEY)) {
            throw new AccessDeniedException("There is no valid RFID key for authentication");
        }

        String login = req.getParameter("login");
        String password = req.getParameter("password");
        String from = req.getParameter("from");
        String app = req.getParameter("app");

        if (!rfidKEY.equals(password)) throw new AccessDeniedException("Incorrect RFID key");

        if (!StringUtils.hasText(from) || !StringUtils.hasText(login)) {
            throw new RequestErrorException("FROM and LOGIN parameter must not be empty string");
        }

        String continueUrl;
        try {
            continueUrl = new String(Base64.getUrlDecoder().decode(from));
        } catch (IllegalArgumentException e) {
            throw new RequestErrorException("Invalid Base64 scheme for FROM parameter for RFID authentication");
        }
        if (!isValidRedirectUrl(continueUrl)) {
            throw new RequestErrorException("Invalid FROM parameter for RFID authentication");
        }
        securityContextService.updateSecurityContextHolder(req, login);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String accessToken = jwtService.authenticateWithJWT(req, resp, authentication, "RFID");

        try {
            if (app != null) {
                accessToken = jwtService.authenticateWithJWT(req, authentication, app);
            }
        } catch (Exception e) {
            throw new RequestErrorException(e.getMessage());
        }

        String redirectURL = UriComponentsBuilder.fromHttpUrl(continueUrl)
                .queryParam("token", accessToken)
                .queryParam("serverTime", System.currentTimeMillis())
                .queryParam(CookieName.RFID.getName())
                .toUriString();
        return REDIRECT_CMD + redirectURL;
    }

    @PreAuthorize("hasAuthority('REVOKE_TOKEN')")
    @ResponseBody
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PostMapping("/fast/prepare_logout")
    void prepareLogout(@RequestHeader("Revoke-Token") String token) {
        jwtService.revokeToken(token);
    }

    private boolean isValidRedirectUrl(String url) {
        return StringUtils.hasText(url) && UrlUtils.isValidRedirectUrl(url);
    }
}
