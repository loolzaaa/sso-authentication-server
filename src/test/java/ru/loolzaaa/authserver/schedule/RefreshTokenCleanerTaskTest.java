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

import static org.junit.jupiter.api.Assertions.*;
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
    void shouldThrowExceptionIfTokenTtlInvalid() throws Exception {
        given(jwtUtils.getRefreshTokenTtl()).willReturn(-100);

        assertThrows(IllegalArgumentException.class, () -> refreshTokenCleanerTask.clean());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void shouldCleanOldRefreshTokens(int count) throws Exception {
        given(jwtUtils.getRefreshTokenTtl()).willReturn(100000000);
        given(jdbcTemplate.update(anyString())).willReturn(count);

        refreshTokenCleanerTask.clean();
    }

    @Test
    void shouldCorrectWorkIfDbError() throws Exception {
        given(jwtUtils.getRefreshTokenTtl()).willReturn(100000000);
        when(jdbcTemplate.update(anyString())).thenThrow(RuntimeException.class);

        refreshTokenCleanerTask.clean();
    }
}