package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import static org.assertj.core.api.Assertions.assertThat;

class IgnoredPathsHandlerTest {

    SsoServerProperties ssoServerProperties;

    IgnoredPathsHandler ignoredPathsHandler;

    @BeforeEach
    void setUp() {
        ssoServerProperties = new SsoServerProperties();
        ignoredPathsHandler = new IgnoredPathsHandler(ssoServerProperties);
    }

    @Test
    void shouldReturnCorrectSizeOfAntPatterns() {
        String[] patterns = ignoredPathsHandler.toAntPatterns();

        assertThat(patterns).hasSize(3);
    }

    @Test
    void shouldReturnTrueForCheckRefreshUriPattern() {
        boolean check = ignoredPathsHandler.checkUri(ssoServerProperties.getRefreshUri());

        assertThat(check).isTrue();
    }

    @Test
    void shouldReturnFalseForCheckInvalidUriPattern() {
        boolean check = ignoredPathsHandler.checkUri("/invalid");

        assertThat(check).isFalse();
    }

}