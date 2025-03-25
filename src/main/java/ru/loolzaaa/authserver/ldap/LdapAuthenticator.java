package ru.loolzaaa.authserver.ldap;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.text.MessageFormat;
import java.util.*;

/**
 * LDAP authenticator which binds as a user.
 */
public class LdapAuthenticator {

    private static final Logger log = LogManager.getLogger(LdapAuthenticator.class);

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Getter
    private final LdapContextSource contextSource;

    private MessageFormat[] userDnFormats;
    private final Object mutex = new Object();

    @Getter
    @Setter
    private String searchBase = "";
    @Getter
    @Setter
    private String searchFilter;
    @Getter
    private final SearchControls searchControls = new SearchControls();

    @Getter
    @Setter
    private String[] userAttributes;

    /**
     * Create an initialized instance using the {@link LdapContextSource}
     * provided.
     *
     * @param contextSource context source instance
     *                      against which bind operations
     *                      will be performed
     */
    public LdapAuthenticator(LdapContextSource contextSource) {
        assert contextSource != null : "context source must not be null";
        this.contextSource = contextSource;

        this.searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    /**
     * Authenticates as a user and obtains additional information
     * from the directory.
     * <p>
     * If first try to bind a user by dn is failed,
     * then second try to get anonymous context and search a user,
     * bind it after that if search is successful.
     *
     * @param authentication the authentication request
     * @return the details of the successfully authenticated user
     */
    public DirContextAdapter authenticate(Authentication authentication) {
        assert authentication instanceof UsernamePasswordAuthenticationToken :
                "Support only UsernamePasswordAuthenticationToken objects";
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        if (!StringUtils.hasLength(password)) {
            throw new BadCredentialsException(
                    this.messages.getMessage("AbstractLdapAuthenticationProvider.emptyPassword", "Empty Password"));
        }
        DirContextAdapter user = null;
        for (String dn : getUserDns(username)) {
            user = bindUser(dn, username, password, null);
            if (user != null) {
                break;
            }
        }
        if (user == null) {
            log.debug("Failed to bind with any user DNs {}", getUserDns(username));
        }
        if (user == null && searchFilter != null) {
            log.trace("Searching for user with base [{}] and filter [{}]", searchBase, searchFilter);
            SearchResult searchResult = searchForUser(username);
            log.debug("Found user {}", username);
            user = bindUser(searchResult.getNameInNamespace(), username, password, searchResult.getAttributes());
            if (user == null) {
                log.debug("Failed to bind user using {}", searchResult);
            }
        }
        if (user == null) {
            throw new BadCredentialsException(
                    this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        return user;
    }

    /**
     * Receive predefined user distinguished name formats.
     *
     * @param username username for which dn formats
     *                 would be received
     * @return list of predefined user DN formats
     */
    public List<String> getUserDns(String username) {
        if (this.userDnFormats == null) {
            return Collections.emptyList();
        }
        List<String> userDns = new ArrayList<>(userDnFormats.length);
        String[] args = new String[]{Rdn.escapeValue(username)};
        synchronized (mutex) {
            for (MessageFormat formatter : userDnFormats) {
                userDns.add(formatter.format(args));
            }
        }
        return userDns;
    }

    /**
     * Define user distinguished name formats.
     * <p>
     * Example: uid={0},ou=people
     *
     * @param userDnPatterns list of user dn patterns
     */
    public void setUserDnPatterns(String... userDnPatterns) {
        userDnFormats = new MessageFormat[userDnPatterns.length];
        for (int i = 0; i < userDnPatterns.length; i++) {
            userDnFormats[i] = new MessageFormat(userDnPatterns[i]);
        }
    }

    /**
     * Create copy of SearchControls for LDAP context
     * search requests.
     *
     * @return copy instance of SearchControls
     */
    protected SearchControls buildControls() {
        return new SearchControls(searchControls.getSearchScope(), searchControls.getCountLimit(),
                searchControls.getTimeLimit(), searchControls.getReturningAttributes(), true,
                searchControls.getDerefLinkFlag());
    }

    private DirContextAdapter bindUser(String userDnStr, String username, String password, Attributes attributes) {
        LdapName userDn = LdapUtils.newLdapName(userDnStr);
        LdapName fullDn = LdapUtils.prepend(userDn, contextSource.getBaseLdapName());
        log.trace("Attempting to bind as {}", fullDn);
        DirContext ctx = null;
        try {
            ctx = contextSource.getContext(fullDn.toString(), password);
            if (attributes == null || attributes.size() == 0) {
                attributes = ctx.getAttributes(userDn, userAttributes);
            }
            DirContextAdapter result = new DirContextAdapter(attributes, userDn, contextSource.getBaseLdapName());
            log.debug("Bound {}", fullDn);
            return result;
        } catch (NamingException e) {
            if (e instanceof AuthenticationException) {
                log.trace(String.format("Failed to bind as %s", userDnStr), e);
            } else {
                throw new RuntimeException(e);
            }
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception ex) {
                    log.debug("Closing LDAP context exception", ex);
                }
            }
        }
        return null;
    }

    private SearchResult searchForUser(String username) {
        log.trace("Searching for user {}", username);
        DirContext ctx = contextSource.getAnonymousContext();

        NamingEnumeration<SearchResult> resultsEnum = null;
        Set<SearchResult> results = new HashSet<>();
        try {
            LdapName ctxBaseDn = LdapUtils.newLdapName(ctx.getNameInNamespace());
            LdapName searchBaseDn = LdapUtils.newLdapName(searchBase);

            resultsEnum = ctx.search(searchBaseDn, searchFilter, new String[]{username}, buildControls());
            log.trace("Searching for entry under DN {}, base = {}, filter = {}",
                    ctxBaseDn, searchBaseDn, searchFilter);

            while (resultsEnum.hasMore()) {
                SearchResult searchResult = resultsEnum.next();
                log.debug("Found result: {}", searchResult);
                results.add(searchResult);
            }
        } catch (NamingException e) {
            if (resultsEnum != null) {
                try {
                    resultsEnum.close();
                } catch (Exception ex) {
                    log.debug("Result enumeration closing error", ex);
                }
            }
            throw new RuntimeException(e);
        }
        if (results.size() != 1) {
            if (results.isEmpty()) {
                throw new UsernameNotFoundException("User " + username + " not found in directory");
            }
            throw new RuntimeException("Result entries size must be 1. Actual: " + results.size());
        }
        return results.iterator().next();
    }
}
