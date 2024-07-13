package ru.loolzaaa.authserver.config.security.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("sso.server")
public class SsoServerProperties {

    private String language = "en";

    private String loginPage = "/login";
    private String refreshUri = "/trefresh";
    private String forbiddenUri = "/forbidden";
    private String adminUri = "/admin";

    private final Application application = new Application();

    private final Rfid rfid = new Rfid();

    private final Cookie cookie = new Cookie();

    @Getter
    @Setter
    public static class Application {
        private String name;
    }

    @Getter
    @Setter
    public static class Rfid {
        private boolean activate;
    }

    @Getter
    @Setter
    public static class Cookie {
        private String sameSite = "Lax";
    }
}
