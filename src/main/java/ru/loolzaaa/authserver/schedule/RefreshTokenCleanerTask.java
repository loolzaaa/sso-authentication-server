package ru.loolzaaa.authserver.schedule;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.concurrent.Callable;

@Log4j2
@RequiredArgsConstructor
@Component
@Profile("prod")
public class RefreshTokenCleanerTask implements Callable<Integer> {

    private final JdbcTemplate jdbcTemplate;

    @Scheduled(initialDelay = 60 * 1000, fixedDelay = 24 * 60 * 60 * 1000)
    @Override
    public Integer call() {
        int i = 0;
        try {
            Timestamp now = Timestamp.valueOf(LocalDateTime.now());
            i = jdbcTemplate.update("DELETE FROM refresh_sessions WHERE expires_in < ?", now);
            log.info("Refresh tokens remove: [{}]", i);
        } catch (Exception e) {
            log.error("Some problem with refresh token cleaner: ", e);
        }
        return i;
    }
}
