package ru.loolzaaa.authserver.config.security.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@ConfigurationProperties("sso.server.basic")
public class BasicUsersProperties {

    private final List<BasicUser> users = new ArrayList<>();
    private String basicUserAuthority = "FAST_SERVICE_REQUEST";

    private String revokeUsername = "REVOKE_TOKEN_USER";
    private String revokePassword = "REVOKE_TOKEN_USER_PASSWORD";
    private String revokeAuthority = "REVOKE_TOKEN";

    @Getter
    @Setter
    public static class BasicUser {
        private String username;
        private String password;
    }
}
