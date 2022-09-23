package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CustomPBKDF2PasswordEncoderTest {

    CustomPBKDF2PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        passwordEncoder = new CustomPBKDF2PasswordEncoder();
    }

    @Test
    void shouldSuccessfullyGenerateSaltAndHashAndMatch() {
        final String salt = passwordEncoder.generateSalt();
        final String rawPassword = "pass";

        assertNotNull(salt);

        passwordEncoder.setSalt(salt);
        String hash = passwordEncoder.encode(rawPassword);
        passwordEncoder.setSalt(null);

        assertNotNull(hash);

        passwordEncoder.setSalt(salt);
        boolean match = passwordEncoder.matches(rawPassword, hash);
        passwordEncoder.setSalt(null);

        assertTrue(match);

        System.out.println("Raw password: " + rawPassword);
        System.out.println("Salt: " + salt);
        System.out.println("Hash: " + hash);
    }
}