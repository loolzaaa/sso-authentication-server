package ru.loolzaaa.authserver.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JWTUtilsTest {

    JWTUtils jwtUtils;

    @ParameterizedTest
    @ValueSource(strings = { "", "classpath:keystore", "classpath:keystore/" })
    void shouldCorrectWorkWithPathKeys(String keyPath) throws Exception {
        jwtUtils = new JWTUtils(keyPath);
        final String claimName = "TEST";
        final String claimValue = "CLAIM";
        Map<String, Object> testClaim = Map.of(claimName, claimValue);

        String token = jwtUtils.buildAccessToken(new Date(), new Date().getTime(), testClaim);
        System.err.println(token);
        Jws<Claims> claimsJws = jwtUtils.parserEnforceAccessToken(token);

        assertNotNull(claimsJws);
        assertNotNull(claimsJws.getPayload());
        assertEquals(claimValue, claimsJws.getPayload().get(claimName));
    }

    @Test
    void shouldThrowExceptionSomeKeyFileNotFound() {
        assertThrows(IOException.class, () -> new JWTUtils("ERR.KEY"));
    }
}