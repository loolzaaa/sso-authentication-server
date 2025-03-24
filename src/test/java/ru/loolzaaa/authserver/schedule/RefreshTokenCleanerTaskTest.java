package ru.loolzaaa.authserver.schedule;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import ru.loolzaaa.authserver.config.security.JWTUtils;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenCleanerTaskTest {

    @Mock
    JWTUtils jwtUtils;
    @Mock
    JdbcTemplate jdbcTemplate;

    RefreshTokenCleanerTask refreshTokenCleanerTask;

    @BeforeEach
    void setUp() {
        refreshTokenCleanerTask = new RefreshTokenCleanerTask(jdbcTemplate, jwtUtils);
    }

    @Test
    void shouldThrowExceptionIfTokenTtlInvalid() {
        given(jwtUtils.getRefreshTokenTtl()).willReturn(Duration.ZERO);

        assertThrows(IllegalArgumentException.class, () -> refreshTokenCleanerTask.clean());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void shouldCleanOldRefreshTokens(int count) {
        given(jwtUtils.getRefreshTokenTtl()).willReturn(Duration.ofHours(10));
        given(jdbcTemplate.update(anyString())).willReturn(count);

        assertDoesNotThrow(() -> refreshTokenCleanerTask.clean());
    }

    @Test
    void shouldCorrectWorkIfDbError() {
        given(jwtUtils.getRefreshTokenTtl()).willReturn(Duration.ofHours(10));
        when(jdbcTemplate.update(anyString())).thenThrow(RuntimeException.class);

        assertDoesNotThrow(() -> refreshTokenCleanerTask.clean());
    }
}