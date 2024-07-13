package ru.loolzaaa.authserver.services;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.support.DataAccessUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import ru.loolzaaa.authserver.config.security.JWTUtils;
import ru.loolzaaa.authserver.model.JWTAuthentication;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

@Log4j2
@RequiredArgsConstructor
@Service
public class JWTService {

    private static final String LOGIN_CLAIM_NAME = "login";
    private static final String AUTHORITIES_CLAIM_NAME = "authorities";

    private final CookieService cookieService;

    private final JWTUtils jwtUtils;

    private final JdbcTemplate jdbcTemplate;

    private final UserRepository userRepository;

    private final List<RevokeToken> revokedTokens = new CopyOnWriteArrayList<>();

    public String authenticateWithJWT(HttpServletRequest req, HttpServletResponse resp,
                                      Authentication authentication, String fingerprint) {
        UserPrincipal user = (UserPrincipal) authentication.getPrincipal();
        List<String> authorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        JWTAuthentication jwtAuthentication = generateJWTAuthentication(user.getUsername(), authorities);

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

        log.info("User {}[{}] logged in. RFID: {}", user.getUsername(), req.getRemoteAddr(), isRfid);

        return jwtAuthentication.getAccessToken();
    }

    public String authenticateWithJWT(HttpServletRequest req, Authentication authentication, String applicationName) {
        UserPrincipal user = (UserPrincipal) authentication.getPrincipal();
        user = new UserPrincipal(user.getUser(), applicationName);
        List<String> authorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Map<String, Object> params = new HashMap<>();
        params.put(LOGIN_CLAIM_NAME, user.getUsername());
        params.put(AUTHORITIES_CLAIM_NAME, authorities);
        Date now = new Date();
        long accessExp = now.getTime() + jwtUtils.getAccessTokenTtl().toMillis();
        String accessToken = jwtUtils.buildAccessToken(now, accessExp, params);

        log.info("Authenticate user {}[{}] for application: {}", user.getUsername(), req.getRemoteAddr(), applicationName);

        return accessToken;
    }

    public String checkAccessToken(String token) {
        Claims claims = parseTokenClaims(token, false);
        String login = getLoginFromClaims(claims);
        if (login != null) {
            log.debug("Success check token for {}", login);
            return login;
        } else {
            return null;
        }
    }

    public JWTAuthentication refreshAccessToken(HttpServletRequest req, HttpServletResponse resp,
                                                String oldAccessToken, String refreshToken) {
        String currentApplication = req.getParameter("_app");
        String currentFingerprint = req.getParameter("_fingerprint");

        String sql = "SELECT login, fingerprint " +
                     "FROM refresh_sessions, users " +
                     "WHERE refresh_token = ?::uuid AND refresh_sessions.user_id = users.id " +
                     "AND (fingerprint = ? OR fingerprint = 'RFID')";
        Map<String, Object> stringObjectMap;
        try {
            stringObjectMap = jdbcTemplate.queryForMap(sql, refreshToken, currentFingerprint);
        } catch (DataAccessException e) {
            log.debug("Error while get refresh token from db: {}", e.getLocalizedMessage());
            return null;
        }

        String username = (String) stringObjectMap.get(LOGIN_CLAIM_NAME);
        String oldFingerprint = (String) stringObjectMap.get("fingerprint");

        Claims claims = parseTokenClaims(oldAccessToken, true);
        String login = getLoginFromClaims(claims);
        if (!username.equals(login)) {
            log.error("Incorrect login in access token claim. Expected: {}, Actual: {}", username, login);
            return null;
        }

        Object authorities = claims.get(AUTHORITIES_CLAIM_NAME);
        if (authorities == null) {
            log.warn("There is no authorities in access token for {}", username);
            return null;
        }

        JWTAuthentication jwtAuthentication = generateJWTAuthentication(username, authorities);

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

        if (currentApplication != null) {
            User user = userRepository.findByLogin(username).orElse(null);
            UserPrincipal userPrincipal = new UserPrincipal(user, currentApplication);
            authorities = userPrincipal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            jwtAuthentication = generateJWTAuthentication(username, authorities);
        }

        log.debug("Refresh token for user {}[{}]. RFID: {}. App: {}",
                username, req.getRemoteAddr(), isRfid, currentApplication);

        return jwtAuthentication;
    }

    public void deleteTokenFromDatabase(String refreshToken) {
        String sql = "SELECT login " +
                     "FROM refresh_sessions, users " +
                     "WHERE refresh_token = ?::uuid AND refresh_sessions.user_id = users.id";
        String username = DataAccessUtils.singleResult(jdbcTemplate.queryForList(sql, String.class, refreshToken));
        if (username == null) {
            log.warn("Cannot find user with token [{}] in database!", refreshToken);
        }

        int count = jdbcTemplate.update("DELETE FROM refresh_sessions WHERE refresh_token = ?::uuid", refreshToken);
        if (count > 0) {
            log.info("User [{}] logged out. Refresh token for this session successfully deleted.", username);
        } else {
            log.warn("User [{}] logged out. There is no tokens in db for this user.", username);
        }
    }

    public void revokeToken(String token) {
        log.debug("Revoke token: {}", token);
        revokedTokens.add(new RevokeToken(token, LocalDateTime.now()));
    }

    public boolean checkTokenForRevoke(String token) {
        return revokedTokens.remove(new RevokeToken(token, null));
    }

    private JWTAuthentication generateJWTAuthentication(String username, Object authorities) {
        Map<String, Object> params = new HashMap<>();
        params.put(LOGIN_CLAIM_NAME, username);
        params.put(AUTHORITIES_CLAIM_NAME, authorities);
        Date now = new Date();
        long accessExp = now.getTime() + jwtUtils.getAccessTokenTtl().toMillis();
        long refreshExp = now.getTime() + jwtUtils.getRefreshTokenTtl().toMillis();
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

    private Claims parseTokenClaims(String token, boolean ignoreClaimException) {
        try {
            return jwtUtils.parserEnforceAccessToken(token).getPayload();
        } catch (ClaimJwtException e) {
            if (ignoreClaimException) {
                return e.getClaims();
            } else {
                log.debug("Failed check token for {}. Error: {}", e.getClaims().get(LOGIN_CLAIM_NAME), e.getMessage());
                return null;
            }
        } catch (Exception e) {
            log.warn("Unknown JWT validation error: {}", e.getMessage());
            return null;
        }
    }

    private String getLoginFromClaims(Claims claims) {
        if (claims == null) {
            return null;
        }
        return claims.get(LOGIN_CLAIM_NAME, String.class);
    }

    @Scheduled(initialDelay = 1, fixedDelay = 60, timeUnit = TimeUnit.MINUTES)
    public void cleanRevokedTokens() {
        LocalDateTime now = LocalDateTime.now();
        revokedTokens.removeIf(revokeToken -> now.minusHours(1L).isAfter(revokeToken.revokeTime()));
    }

    private record RevokeToken(String token, LocalDateTime revokeTime) {
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
