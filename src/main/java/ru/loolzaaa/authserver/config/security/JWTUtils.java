package ru.loolzaaa.authserver.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;

@Component
public class JWTUtils {

    private final String accessSecretKey = "dUYzUFY4UVN6MkpXenpKbThzaFhmd0U2eElOdFlzZmQzZGN4Sk8xTTA5RDBWR014RElpTElkNndtTmYyaDRkMQ==";

    private final int ACCESS_TOKEN_TTL = 5 * 6 * 1000; // 5 Minutes (30 sec)
    private final int REFRESH_TOKEN_TTL = 10 * 60 * 60 * 1000; // 10 Hours

    public String buildAccessToken(Date issuedAt, long exp, Map<String, Object> params) {
        return Jwts.builder()
                .setIssuedAt(issuedAt)
                .setExpiration(new Date(exp))
                .addClaims(params)
                .signWith(SignatureAlgorithm.HS256, getHS256SecretBytes(accessSecretKey))
                .compact();
    }

    public Jws<Claims> parserEnforceAccessToken(String jwt) {
        return Jwts.parser()
                .setAllowedClockSkewSeconds(30)
                .setSigningKey(getHS256SecretBytes(accessSecretKey))
                .parseClaimsJws(jwt);
    }

    private byte[] getHS256SecretBytes(String key) {
        return TextCodec.BASE64.decode(key);
    }

    public int getAccessTokenTtl() {
        return ACCESS_TOKEN_TTL;
    }

    public int getRefreshTokenTtl() {
        return REFRESH_TOKEN_TTL;
    }
}
