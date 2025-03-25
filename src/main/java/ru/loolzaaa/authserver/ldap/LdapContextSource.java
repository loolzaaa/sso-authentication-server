package ru.loolzaaa.authserver.ldap;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.loolzaaa.authserver.config.security.property.LdapServerProperties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.ListIterator;

/**
 * Ldap context source implementation which creates
 * an <code>InitialLdapContext</code> instance.
 *
 * @see LdapServerProperties
 */
public class LdapContextSource {

    private static final Logger log = LogManager.getLogger(LdapContextSource.class);

    private static final String CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    private final Hashtable<String, Object> baseEnv = new Hashtable<>();

    private final String url;

    private LdapName base;

    @Getter
    @Setter
    private String referral;

    @Getter
    @Setter
    private String domain;

    /**
     * Creates LDAP context source with supplied provider URL.
     * <p>
     * Also, this constructor extract root DN from provider url.
     *
     * @param providerUrl LDAP provider url
     */
    public LdapContextSource(String providerUrl) {
        assert providerUrl != null && !providerUrl.isEmpty() : "An LDAP connection URL must be supplied";
        String urlRootDn = LdapUtils.parseRootDnFromUrl(providerUrl);
        log.info("Configure LDAP context with URL {} and root DN '{}'", providerUrl, urlRootDn);
        this.url = providerUrl.substring(0, providerUrl.lastIndexOf(urlRootDn));
        setBase(urlRootDn);
        setupBaseEnv();
    }

    /**
     * Creates bounded LDAP context.
     * <p>
     * This context should be bound to concrete user
     * with supplied credentials if it is valid.
     *
     * @param principal username
     * @param password  password
     * @return LDAP context bounded to user
     * @throws NamingException if invalid credentials
     *                         or some LDAP server error
     */
    public DirContext getContext(String principal, String password) throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>(baseEnv);
        env.put(Context.SECURITY_PRINCIPAL, principal);
        env.put(Context.SECURITY_CREDENTIALS, password);

        return createContext(env);
    }

    /**
     * Creates anonymous LDAP context.
     * <p>
     * This context bound to anonymous user, it allows
     * to search concrete user and bound to ir with found
     * user DN.
     *
     * @return anonymous LDAP context
     */
    public DirContext getAnonymousContext() {
        try {
            return createContext(baseEnv);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Receive copy of root DN for this context source.
     *
     * @return cloned version of current root DN
     */
    public LdapName getBaseLdapName() {
        return (LdapName) base.clone();
    }

    /**
     * Set root distinguished name as search base for LDAP queries.
     *
     * @param base url root DN to be set
     */
    public void setBase(String base) {
        String decodedBase = URLDecoder.decode(base, StandardCharsets.UTF_8);
        this.base = LdapUtils.newLdapName(decodedBase);
    }

    /**
     * Setup base environment variables for LDAP connection.
     * <p>
     * You must invoke this method if change some environment
     * variables after context source creation.
     */
    public void setupBaseEnv() {
        baseEnv.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
        StringBuilder providerUrlBuilder = new StringBuilder(url);
        if (!base.isEmpty()) {
            if (!url.endsWith("/")) {
                providerUrlBuilder.append("/");
            }
        }
        List<String> rdnStrings = new ArrayList<>(base.getRdns().size());
        ListIterator<Rdn> it = base.getRdns().listIterator(base.size());
        while (it.hasPrevious()) {
            rdnStrings.add(it.previous().toString());
        }
        providerUrlBuilder.append(String.join(",", rdnStrings));
        baseEnv.put(Context.PROVIDER_URL, providerUrlBuilder.toString().trim());
        if (referral != null && !referral.isEmpty()) {
            baseEnv.put(Context.REFERRAL, referral);
        }
        if (domain != null && !domain.isEmpty()) {
            baseEnv.put("com.sun.jndi.ldap.domainname", domain);
        }
        baseEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
    }

    private DirContext createContext(Hashtable<String, Object> env) throws NamingException {
        DirContext ctx = null;
        try {
            ctx = new InitialLdapContext(env, null);
            log.debug("Got LDAP context on server: " + ctx.getEnvironment().get(Context.PROVIDER_URL));
            return ctx;
        } catch (NamingException e) {
            closeContext(ctx);
            throw e;
        }
    }

    private void closeContext(DirContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (Exception ex) {
                log.debug("Closing LDAP context exception", ex);
            }
        }
    }
}
