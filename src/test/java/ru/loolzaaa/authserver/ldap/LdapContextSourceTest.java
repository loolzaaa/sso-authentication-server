package ru.loolzaaa.authserver.ldap;

import org.junit.jupiter.api.*;
import org.springframework.test.util.ReflectionTestUtils;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
class LdapContextSourceTest {

    private static final String LDAP_HOST = "ldap.forumsys.com";
    private static final int LDAP_PORT = 389;

    LdapContextSource contextSource;

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
        contextSource = new LdapContextSource("ldap://" + LDAP_HOST + ":" + LDAP_PORT);
    }

    @Test
    public void shouldCorrectCreateContextSource() {
        LdapContextSource cs = new LdapContextSource("ldap://example.ru/dc=example,dc=ru");
        String url = (String) ReflectionTestUtils.getField(cs, "url");

        assertEquals("ldap://example.ru/", url);
        assertEquals(cs.getBaseLdapName().toString(), "dc=example,dc=ru");
    }

    @Test
    public void shouldCreateAnonymousContext() {
        DirContext ctx = contextSource.getAnonymousContext();

        assertNotNull(ctx);
        assertInstanceOf(InitialDirContext.class, ctx);
    }

    @Test
    public void shouldCreateAuthenticatedContext() throws Exception {
        DirContext ctx = contextSource.getContext("cn=read-only-admin,dc=example,dc=com", "password");

        assertNotNull(ctx);
        assertInstanceOf(InitialDirContext.class, ctx);
    }
}