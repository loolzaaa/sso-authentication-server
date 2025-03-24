package ru.loolzaaa.authserver.config.security.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("sso.server.ldap")
public class LdapServerProperties {
    private boolean enabled;
    private String mode;
    private String providerUrl;
    private String domain;
    private String referral;
    private String[] userDnPatterns;
    private String searchBase;
    private String searchFilter;
    private String[] userAttributes;
}
