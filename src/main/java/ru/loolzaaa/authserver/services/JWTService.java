package ru.loolzaaa.authserver.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import ru.loolzaaa.authserver.config.security.JWTUtils;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.model.UserPrincipal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
@Service
public class JWTService {

    private final CookieService cookieService;

    private final JWTUtils jwtUtils;

    private final JdbcTemplate jdbcTemplate;

    private final List<RevokeToken> revokedTokens = new CopyOnWriteArrayList<>();

    public String authenticateWithJWT(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) {
        String fingerprint = req.getParameter("_fingerprint");
        return authenticateWithJWT(req, resp, authentication, fingerprint);
    }

    public String authenticateWithJWT(HttpServletRequest req, HttpServletResponse resp,
                                    Authentication authentication, String fingerprint) {
        UserPrincipal user = (UserPrincipal) authentication.getPrincipal();

        JWTAuthentication jwtAuthentication = generateJWTAuthentication(req, resp, user.getUsername());

        String sql = "INSERT INTO refresh_sessions " +
                "(user_id, refresh_token, expires_in, fingerprint) " +
                "VALUES (?, ?, ?, ?)";
        jdbcTemplate.update(
                sql,
                user.getId(),
                jwtAuthentication.getRefreshToken(),
                new Timestamp(jwtAuthentication.getRefreshExp()),
                fingerprint
        );

        boolean isRfid = "RFID".equals(fingerprint);
        cookieService.updateTokenCookies(req, resp,
                jwtAuthentication.getAccessToken(),
                jwtAuthentication.getRefreshToken().toString(),
                isRfid);

        //log.info("User {}[{}] logged in.", login, req.getRemoteAddr());

        return jwtAuthentication.getAccessToken();
    }

    public String checkAccessToken(String token) {
        try {
            Jws<Claims> claims = jwtUtils.parserEnforceAccessToken(token);
            return (String) claims.getBody().get("login");
        } catch (Exception e) {
            return null;
        }
    }

    public JWTAuthentication refreshAccessToken(HttpServletRequest req, HttpServletResponse resp, String refreshToken) {
        String currentFingerprint = req.getParameter("_fingerprint");

        String sql = "SELECT login, fingerprint " +
                "FROM refresh_sessions, users " +
                "WHERE refresh_token = ?::uuid AND refresh_sessions.user_id = users.id " +
                "AND (fingerprint = ? OR fingerprint = 'RFID')";
        Map<String, Object> stringObjectMap;
        try {
            stringObjectMap = jdbcTemplate.queryForMap(sql, refreshToken, currentFingerprint);
        } catch (DataAccessException e) {
            return null;
        }

        String username = (String) stringObjectMap.get("login");
        String oldFingerprint = (String) stringObjectMap.get("fingerprint");

        JWTAuthentication jwtAuthentication = generateJWTAuthentication(req, resp, username);

        jdbcTemplate.update("UPDATE refresh_sessions " +
                        "SET refresh_token = ?::uuid, expires_in = ?, fingerprint = ? " +
                        "WHERE refresh_token = ?::uuid AND fingerprint = ?",
                jwtAuthentication.getRefreshToken(),
                new Timestamp(jwtAuthentication.getRefreshExp()),
                currentFingerprint,
                refreshToken,
                oldFingerprint);

        boolean isRfid = "RFID".equals(currentFingerprint);
        cookieService.updateTokenCookies(req, resp,
                jwtAuthentication.getAccessToken(),
                jwtAuthentication.getRefreshToken().toString(),
                isRfid);

        return jwtAuthentication;
    }

    public void deleteTokenFromDatabase(String refreshToken) {
        String sql = "SELECT login " +
                "FROM refresh_sessions, users " +
                "WHERE refresh_token = ?::uuid AND refresh_sessions.user_id = users.id";
        String username = DataAccessUtils.singleResult(jdbcTemplate.queryForList(sql, String.class, refreshToken));
        //if (username == null) log.warn("Cannot find user with token [{}] in database!", token);

        int count = jdbcTemplate.update("DELETE FROM refresh_sessions WHERE refresh_token = ?::uuid", refreshToken);
        if (count > 0) {
            //log.info("User [{}] logged out. Refresh token for this session successfully deleted.", login);
        } else {
            //log.warn("User [{}] logged out. There is no tokens in db for this user.", login);
        }
    }

    public void revokeToken(String token) {
        revokedTokens.add(new RevokeToken(token, LocalDateTime.now()));
    }

    public boolean checkTokenForRevoke(String token) {
        return revokedTokens.remove(new RevokeToken(token, null));
    }

    private JWTAuthentication generateJWTAuthentication(HttpServletRequest req, HttpServletResponse resp, String username) {
        Map<String, Object> params = new HashMap<>();
        params.put("login", username);
        Date now = new Date();
        long accessExp = now.getTime() + jwtUtils.getAccessTokenTtl();
        long refreshExp = now.getTime() + jwtUtils.getRefreshTokenTtl();
        String accessToken = jwtUtils.buildAccessToken(now, accessExp, params);
        UUID refreshToken = UUID.randomUUID();

        return JWTAuthentication.builder()
                .username(username)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessExp(accessExp)
                .refreshExp(refreshExp)
                .build();
    }

    @Scheduled(initialDelay = 1, fixedDelay = 60, timeUnit = TimeUnit.MINUTES)
    public void cleanRevokedTokens() {
        LocalDateTime now = LocalDateTime.now();
        revokedTokens.removeIf(revokeToken -> now.minusHours(1L).isAfter(revokeToken.getRevokeTime()));
    }

    @RequiredArgsConstructor
    @Getter
    private static class RevokeToken {
        private final String token;
        private final LocalDateTime revokeTime;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RevokeToken that = (RevokeToken) o;
            return token.equals(that.token);
        }

        @Override
        public int hashCode() {
            return Objects.hash(token);
        }
    }
}
