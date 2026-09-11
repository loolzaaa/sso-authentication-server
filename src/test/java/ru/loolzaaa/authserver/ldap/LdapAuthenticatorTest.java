package ru.loolzaaa.authserver.ldap;

import org.junit.jupiter.api.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
class LdapAuthenticatorTest {

    private static final String LDAP_HOST = "ldap.forumsys.com";
    private static final int LDAP_PORT = 389;

    LdapAuthenticator authenticator;

    @BeforeAll
    static void checkHost() {
        Assumptions.assumeTrue(isLdapHostReachable(), "LDAP host " + LDAP_HOST + ":" + LDAP_PORT + " is unreachable");
    }

    private static boolean isLdapHostReachable() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(LDAP_HOST, LDAP_PORT), 2000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @BeforeEach
    public void setUp() {
        LdapContextSource contextSource = new LdapContextSource("ldap://" + LDAP_HOST + ":" + LDAP_PORT);

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