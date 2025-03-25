package ru.loolzaaa.authserver.ldap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.net.URI;
import java.net.URISyntaxException;

public final class LdapUtils {

    /**
     * Extract root DN from LDAP URL.
     * <p>
     * For example, the URL <tt>ldap://example.com:10389/dc=example,dc=org</tt>
     * has the root DN "dc=example,dc=org".
     *
     * @param url the LDAP URL
     * @return the root DN
     */
    public static String parseRootDnFromUrl(String url) {
        assert url != null && !url.isEmpty() : "Url must have length";
        String urlRootDn;
        if (url.startsWith("ldap:") || url.startsWith("ldaps:")) {
            URI uri;
            try {
                uri = new URI(url);
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Unable to parse url: " + url, e);
            }
            urlRootDn = uri.getRawPath();
        } else {
            throw new IllegalArgumentException("Url must starts with 'ldap:' or 'ldaps:'");
        }
        if (urlRootDn.startsWith("/")) {
            urlRootDn = urlRootDn.substring(1);
        }
        return urlRootDn;
    }

    /**
     * Construct a new LdapName instance from the supplied
     * distinguished name string.
     *
     * @param distinguishedName the string DN to parse
     * @return a new LdapName instance
     */
    public static LdapName newLdapName(String distinguishedName) {
        assert distinguishedName != null : "distinguishedName must not be null";
        try {
            return new LdapName(distinguishedName);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException("Illegal distinguishedName for LDAP name creation", e);
        }
    }

    /**
     * Prepend the supplied path in the beginning
     * the specified <code>LdapName</code> if the
     * name instance starts with <code>path</code>.
     * <p>
     * The original Name will not be affected.
     *
     * @param dn            the dn to strip from
     * @param pathToPrepend the path to prepend in
     *                      the beginning of the dn
     * @return an LdapName instance that is a copy
     * of the original name with the specified path
     * inserted at its beginning.
     */
    public static LdapName prepend(LdapName dn, LdapName pathToPrepend) {
        assert dn != null : "dn must not be null";
        assert pathToPrepend != null : "pathToPrepend must not be null";

        LdapName result = (LdapName) dn.clone();
        try {
            result.addAll(0, pathToPrepend);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException("Cannot prepend " + pathToPrepend + " to " + dn, e);
        }
        return result;
    }
}
