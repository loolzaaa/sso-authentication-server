package ru.loolzaaa.authserver.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

@Component
public class JWTUtils {

    private static final String accessSecretKey = "dUYzUFY4UVN6MkpXenpKbThzaFhmd0U2eElOdFlzZmQzZGN4Sk8xTTA5RDBWR014RElpTElkNndtTmYyaDRkMQ==";

    @Value("${sso.server.jwt.access-ttl:30s}")
    private Duration accessTokenTtl;
    @Value("${sso.server.jwt.refresh-ttl:10h}")
    private Duration refreshTokenTtl;

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

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }
}
