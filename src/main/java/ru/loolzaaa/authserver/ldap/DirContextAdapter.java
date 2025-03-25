package ru.loolzaaa.authserver.ldap;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;

/**
 * Adapter for bounded user from LDAP context.
 * <p>
 * Contains user attributes and full distinguished name
 * of user, separated on two parts: base and user.
 */
@Getter
@RequiredArgsConstructor
public class DirContextAdapter {
    private final Attributes attributes;
    private final LdapName userDn;
    private final LdapName baseDn;
}
