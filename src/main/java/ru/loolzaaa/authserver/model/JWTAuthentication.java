package ru.loolzaaa.authserver.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class JWTAuthentication {
    private String username;
    private String accessToken;
    private String refreshToken;
    private long accessExp;
    private long refreshExp;
}
