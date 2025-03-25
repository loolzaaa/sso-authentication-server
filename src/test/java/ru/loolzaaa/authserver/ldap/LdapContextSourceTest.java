package ru.loolzaaa.authserver.ldap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import static org.junit.jupiter.api.Assertions.*;

class LdapContextSourceTest {

    LdapContextSource contextSource;

    @BeforeEach
    public void setUp() {
        contextSource = new LdapContextSource("ldap://ldap.forumsys.com:389");
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