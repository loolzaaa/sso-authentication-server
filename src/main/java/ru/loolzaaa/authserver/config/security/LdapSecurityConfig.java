package ru.loolzaaa.authserver.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import ru.loolzaaa.authserver.config.security.bean.LdapAuthenticationProvider;
import ru.loolzaaa.authserver.config.security.property.LdapServerProperties;
import ru.loolzaaa.authserver.ldap.ActiveDirectoryLdapAuthenticator;
import ru.loolzaaa.authserver.ldap.LdapAuthenticator;
import ru.loolzaaa.authserver.ldap.LdapContextSource;

@RequiredArgsConstructor
@EnableConfigurationProperties(LdapServerProperties.class)
@Configuration
public class LdapSecurityConfig {

    private final LdapServerProperties ldapServerProperties;

    @Qualifier("jwtUserDetailsService")
    private final UserDetailsService userDetailsService;

    @ConditionalOnProperty(prefix = "sso.server.ldap", value = "enabled")
    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        LdapContextSource contextSource = new LdapContextSource(ldapServerProperties.getProviderUrl());
        if ("ad".equalsIgnoreCase(ldapServerProperties.getMode())) {
            contextSource.setReferral(ldapServerProperties.getReferral());
        }

        LdapAuthenticator authenticator = getLdapAuthenticator(contextSource);
        if (ldapServerProperties.getUserDnPatterns() != null && ldapServerProperties.getUserAttributes().length > 0) {
            authenticator.setUserDnPatterns(ldapServerProperties.getUserDnPatterns());
        }
        if (ldapServerProperties.getSearchBase() != null) {
            authenticator.setSearchBase(ldapServerProperties.getSearchBase());
        }
        if (ldapServerProperties.getSearchFilter() != null) {
            authenticator.setSearchFilter(ldapServerProperties.getSearchFilter());
        }
        if (ldapServerProperties.getUserAttributes() != null && ldapServerProperties.getUserAttributes().length > 0) {
            authenticator.setUserAttributes(ldapServerProperties.getUserAttributes());
        }

        LdapAuthenticationProvider authenticationProvider = new LdapAuthenticationProvider();
        authenticationProvider.setAuthenticator(authenticator);
        authenticationProvider.setUserDetailsService(userDetailsService);
        return authenticationProvider;
    }

    private LdapAuthenticator getLdapAuthenticator(LdapContextSource contextSource) {
        LdapAuthenticator authenticator;
        if ("ldap".equalsIgnoreCase(ldapServerProperties.getMode())) {
            authenticator = new LdapAuthenticator(contextSource);
        } else if ("ad".equalsIgnoreCase(ldapServerProperties.getMode())) {
            authenticator = new ActiveDirectoryLdapAuthenticator(contextSource, ldapServerProperties.getDomain());
        } else {
            throw new IllegalArgumentException("Incorrect LDAP mode: " + ldapServerProperties.getMode());
        }
        return authenticator;
    }
}
