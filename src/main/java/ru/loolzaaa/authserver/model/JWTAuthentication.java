package ru.loolzaaa.authserver.model;

import lombok.Builder;
import lombok.Getter;

import java.util.UUID;

@Getter
@Builder
public class JWTAuthentication {
    private String username;
    private String accessToken;
    private UUID refreshToken;
    private long accessExp;
    private long refreshExp;
}
