package ru.loolzaaa.authserver.controllers;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import ru.loolzaaa.authserver.audit.AuditLogger;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.dto.RequestStatus;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import java.io.IOException;
import java.util.Base64;

@Slf4j
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

    private final AccessDeniedHandler accessDeniedHandler;

    @PostMapping("/refresh")
    String refreshToken(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        String accessToken = cookieService.getCookieValueByName(CookieName.ACCESS.getName(), req.getCookies());
        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());
        if (accessToken == null || refreshToken == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return redirectToLoginOrContinue(req);
        }

        JWTAuthentication jwtAuthentication = jwtService.refreshSsoTokens(req, resp, accessToken, refreshToken);
        if (jwtAuthentication == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return redirectToLoginOrContinue(req);
        }

        // SSO session is valid and has just been extended. Authenticate the current request,
        // so the access denied handler can forward to the protected error page.
        securityContextService.updateSecurityContextHolder(req, jwtAuthentication.getUsername());

        String appToken = null;
        String appParameter = req.getParameter("_app");
        if (appParameter != null) {
            try {
                appToken = jwtService.buildApplicationAccessToken(jwtAuthentication.getUsername(), appParameter);
            } catch (IllegalArgumentException e) {
                log.warn("Access denied for application [{}] for user [{}]: {}",
                        appParameter, jwtAuthentication.getUsername(), e.getLocalizedMessage());
                accessDeniedHandler.handle(req, resp, new AccessDeniedException(e.getLocalizedMessage()));
                return null;
            }
        }

        String continueUrl = decodeContinueUrl(req.getParameter("_continue"));
        if (continueUrl == null) {
            return REDIRECT_CMD + "/";
        }

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(continueUrl);
        if (appToken != null) {
            uriComponentsBuilder
                    .queryParam("token", appToken)
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
            return refreshError(HttpStatus.UNAUTHORIZED, "There is no refresh token");
        }

        JWTAuthentication jwtAuthentication = jwtService.refreshSsoTokens(req, resp, accessToken, refreshToken);
        if (jwtAuthentication == null) {
            securityContextService.clearSecurityContextHolder(req, resp);
            return refreshError(HttpStatus.UNAUTHORIZED, "Refresh token is invalid");
        }

        securityContextService.updateSecurityContextHolder(req, jwtAuthentication.getUsername());

        String token = jwtAuthentication.getAccessToken();
        String appParameter = req.getParameter("_app");
        if (appParameter != null) {
            try {
                token = jwtService.buildApplicationAccessToken(jwtAuthentication.getUsername(), appParameter);
            } catch (IllegalArgumentException e) {
                log.warn("Access denied for application [{}] for user [{}]: {}",
                        appParameter, jwtAuthentication.getUsername(), e.getLocalizedMessage());
                return refreshError(HttpStatus.FORBIDDEN, e.getLocalizedMessage());
            }
        }

        String body = String.format("{\"token\":\"%s\",\"serverTime\":%d}", token, System.currentTimeMillis());
        return ResponseEntity.ok().body(RequestStatusDTO.ok(body));
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

        if (!rfidKEY.equals(password)) {
            AuditLogger.loginFailure(login, req.getRemoteAddr(), "Incorrect RFID key");
            throw new AccessDeniedException("Incorrect RFID key");
        }

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
        AuditLogger.securityEvent("PREPARE_LOGOUT", "revoke token requested");
        jwtService.revokeToken(token);
    }

    private ResponseEntity<RequestStatusDTO> refreshError(HttpStatus status, String text) {
        return ResponseEntity.status(status)
                .body(RequestStatusDTO.builder()
                        .status(RequestStatus.ERROR)
                        .statusCode(status)
                        .text(text)
                        .build());
    }

    private String redirectToLoginOrContinue(HttpServletRequest req) {
        String continueUrl = decodeContinueUrl(req.getParameter("_continue"));
        return continueUrl != null ? REDIRECT_CMD + continueUrl : REDIRECT_CMD + ssoServerProperties.getLoginPage();
    }

    private String decodeContinueUrl(String continuePath) {
        if (continuePath == null) {
            return null;
        }
        try {
            String continueUrl = new String(Base64.getUrlDecoder().decode(continuePath)).replaceAll("[\r\n]", "_");
            return isValidRedirectUrl(continueUrl) ? continueUrl : null;
        } catch (IllegalArgumentException e) {
            log.warn("Continue parameter is not valid Base64 scheme");
            return null;
        }
    }

    private boolean isValidRedirectUrl(String url) {
        return StringUtils.hasText(url) && UrlUtils.isValidRedirectUrl(url);
    }
}
