package ru.loolzaaa.authserver.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.Map;

class JWTUtilsTest {

    JWTUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JWTUtils();
    }

    @Test
    void test() throws Exception {
        Date now = new Date();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String compact = Jwts.builder()
                .setIssuedAt(now)
                .setExpiration(now)
                .addClaims(Map.of())
                .signWith(SignatureAlgorithm.RS256, pair.getPrivate())
                .compact();
        System.out.println(compact);

        Jws<Claims> claimsJws = Jwts.parser()
                .setAllowedClockSkewSeconds(30)
                .setSigningKey(pair.getPublic())
                .parseClaimsJws(compact);
        System.out.println(claimsJws);
    }
}