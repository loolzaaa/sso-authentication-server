package ru.loolzaaa.authserver.schedule;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.config.security.JWTUtils;

import java.util.concurrent.TimeUnit;

@Log4j2
@RequiredArgsConstructor
@Component
@Profile("prod")
public class RefreshTokenCleanerTask {

    private final JdbcTemplate jdbcTemplate;

    private final JWTUtils jwtUtils;

    @Scheduled(initialDelay = 1, fixedDelay = 10, timeUnit = TimeUnit.MINUTES)
    public void clean() {
        int refreshTokenTtl = jwtUtils.getRefreshTokenTtl() / 1000 / 60 / 60;
        if (refreshTokenTtl < 1) {
            throw new IllegalArgumentException("Incorrect refresh token ttl: " + jwtUtils.getRefreshTokenTtl());
        }
        try {
            int i = jdbcTemplate.update(String.format("DELETE FROM refresh_sessions WHERE expires_in < (now() - interval '%d hour')", refreshTokenTtl));
            if (i > 0) {
                log.info("Refresh tokens remove: [{}]", i);
            }
        } catch (Exception e) {
            log.error("Some problem with refresh token cleaner: ", e);
        }
    }
}
