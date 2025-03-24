package ru.loolzaaa.authserver.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Date;
import java.util.Map;

@Component
public class JWTUtils {

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    @Getter
    @Value("${sso.server.jwt.access-ttl:30s}")
    private Duration accessTokenTtl;
    @Getter
    @Value("${sso.server.jwt.refresh-ttl:10h}")
    private Duration refreshTokenTtl;

    public JWTUtils(@Value("${sso.server.jwt.key-path:}") String keyPath) throws IOException, GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        String publicKeyPath = "keystore/public.key";
        String privateKeyPath = "keystore/private.key";
        byte[] publicKeyBytes;
        byte[] privateKeyBytes;
        if (StringUtils.hasText(keyPath)) {
            publicKeyPath = keyPath + "/public.key";
            privateKeyPath = keyPath + "/private.key";

            File publicKeyFile = ResourceUtils.getFile(publicKeyPath);
            publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

            File privateKeyFile = ResourceUtils.getFile(privateKeyPath);
            privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        } else {
            InputStream publicKeyStream = new ClassPathResource(publicKeyPath).getInputStream();
            try (publicKeyStream) {
                publicKeyBytes = publicKeyStream.readAllBytes();
            }
            InputStream privateKeyStream = new ClassPathResource(privateKeyPath).getInputStream();
            try (privateKeyStream) {
                privateKeyBytes = privateKeyStream.readAllBytes();
            }
        }

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        this.publicKey = keyFactory.generatePublic(publicKeySpec);

        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        this.privateKey = keyFactory.generatePrivate(privateKeySpec);
    }

    public String buildAccessToken(Date issuedAt, long exp, Map<String, Object> params) {
        return Jwts.builder()
                .issuedAt(issuedAt)
                .expiration(new Date(exp))
                .claims(params)
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public Jws<Claims> parserEnforceAccessToken(String jwt) {
        return Jwts.parser()
                .clockSkewSeconds(30)
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt);
    }
}
