package ru.loolzaaa.authserver.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;

import java.io.File;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Date;
import java.util.Map;

@Component
public class JWTUtils {

    private final Key publicKey;
    private final Key privateKey;

    @Value("${sso.server.jwt.access-ttl:30s}")
    private Duration accessTokenTtl;
    @Value("${sso.server.jwt.refresh-ttl:10h}")
    private Duration refreshTokenTtl;

    public JWTUtils(@Value("${sso.server.jwt.key-path:}") String keyPath) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        String publicKeyPath = "classpath:keystore/public.key";
        String privateKeyPath = "classpath:keystore/private.key";
        if (StringUtils.hasText(keyPath)) {
            if (keyPath.endsWith("/")) {
                keyPath = keyPath.substring(0, keyPath.lastIndexOf("/"));
            }
            publicKeyPath = keyPath + "/public.key";
            privateKeyPath = keyPath + "/private.key";
        }

        File publicKeyFile = ResourceUtils.getFile(publicKeyPath);
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        this.publicKey = keyFactory.generatePublic(publicKeySpec);

        File privateKeyFile = ResourceUtils.getFile(privateKeyPath);
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        this.privateKey = keyFactory.generatePrivate(privateKeySpec);
    }

    public String buildAccessToken(Date issuedAt, long exp, Map<String, Object> params) {
        return Jwts.builder()
                .setIssuedAt(issuedAt)
                .setExpiration(new Date(exp))
                .addClaims(params)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    public Jws<Claims> parserEnforceAccessToken(String jwt) {
        return Jwts.parser()
                .setAllowedClockSkewSeconds(30)
                .setSigningKey(publicKey)
                .parseClaimsJws(jwt);
    }

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }
}
