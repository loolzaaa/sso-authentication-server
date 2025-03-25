package ru.loolzaaa.authserver.ldap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static org.junit.jupiter.api.Assertions.*;

class LdapAuthenticatorTest {

    LdapAuthenticator authenticator;

    @BeforeEach
    public void setUp() {
        LdapContextSource contextSource = new LdapContextSource("ldap://ldap.forumsys.com:389");

        authenticator = new LdapAuthenticator(contextSource);
    }

    @Test
    public void shouldSuccessAuthenticateWithFullDn() {
        authenticator.setUserDnPatterns("uid={0},dc=example,dc=com");
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken
                .unauthenticated("einstein", "password");

        DirContextAdapter authenticate = authenticator.authenticate(authentication);

        assertNotNull(authenticate);
    }

    @Test
    public void shouldSuccessAuthenticateWithBaseDn() {
        authenticator.setSearchFilter("(uid={0})");
        authenticator.setSearchBase("dc=example,dc=com");
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken
                .unauthenticated("einstein", "password");

        DirContextAdapter authenticate = authenticator.authenticate(authentication);

        assertNotNull(authenticate);
    }
}