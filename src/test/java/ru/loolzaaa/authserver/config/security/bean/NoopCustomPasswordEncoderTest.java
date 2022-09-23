package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class NoopCustomPasswordEncoderTest {

    NoopCustomPasswordEncoder noopCustomPasswordEncoder;

    @BeforeEach
    void setUp() {
        noopCustomPasswordEncoder = new NoopCustomPasswordEncoder();
    }

    @Test
    void shouldMatchDifferentPasswords() {
        boolean matches = noopCustomPasswordEncoder.matches("123", "321");

        assertTrue(matches);
    }
}