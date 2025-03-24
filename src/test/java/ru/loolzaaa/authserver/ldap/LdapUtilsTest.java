package ru.loolzaaa.authserver.ldap;

import org.junit.jupiter.api.Test;

import javax.naming.ldap.LdapName;

import static org.assertj.core.api.Assertions.*;

class LdapUtilsTest {
    @Test
    public void testParseRootDnFromUrl() {
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example")).isEqualTo("");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example:10389")).isEqualTo("");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example/")).isEqualTo("");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example.ru/")).isEqualTo("");
        assertThat(LdapUtils.parseRootDnFromUrl("ldaps://example.ru/dc=example,dc=ru"))
                .isEqualTo("dc=example,dc=ru");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap:///dc=example,dc=ru"))
                .isEqualTo("dc=example,dc=ru");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example/dc=example,dc=ru"))
                .isEqualTo("dc=example,dc=ru");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example.ru/dc=example,dc=ru/ou=blah"))
                .isEqualTo("dc=example,dc=ru/ou=blah");
        assertThat(LdapUtils.parseRootDnFromUrl("ldap://example.ru:389/dc=example,dc=ru/ou=blah"))
                .isEqualTo("dc=example,dc=ru/ou=blah");
        assertThatThrownBy(() -> LdapUtils.parseRootDnFromUrl("example.com:389/dc=example,dc=ru"));
        assertThatThrownBy(() -> LdapUtils.parseRootDnFromUrl("ldap://192.168.0.1/?q=^err"));
    }

    @Test
    public void testNewLdapName() {
        final String dn = "dc=example,dc=ru";
        assertThat(LdapUtils.newLdapName(dn)).isInstanceOf(LdapName.class);
        assertThat(LdapUtils.newLdapName(dn).toString()).isEqualToIgnoringCase(dn);
        assertThatThrownBy(() -> LdapUtils.newLdapName("invalid"));
    }

    @Test
    public void testPrepend() throws Exception {
        LdapName base = new LdapName("dc=ru");
        LdapName pre = new LdapName("dc=example");

        assertThat(LdapUtils.prepend(pre, base)).isInstanceOf(LdapName.class);
        assertThat(LdapUtils.prepend(pre, base).toString()).isEqualToIgnoringCase("dc=example,dc=ru");
    }
}