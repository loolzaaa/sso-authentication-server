package ru.loolzaaa.authserver.ldap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import java.util.*;

/**
 * Active Directory implementation of {@link LdapAuthenticator}.
 * <p>
 * Active Directory binds user not by classic
 * distinguished name, but with username, followed
 * by at-symbol with domain. Also, there is no possible
 * to get anonymous context with this strategy.
 */
public class ActiveDirectoryLdapAuthenticator extends LdapAuthenticator {

    private static final Logger log = LogManager.getLogger(ActiveDirectoryLdapAuthenticator.class);

    /**
     * Create initialized instance of ActiveDirectoryAuthenticator.
     *
     * @param contextSource context source instance
     *                      against which bind operations
     *                      will be performed
     * @param domain        active directory server domain
     */
    public ActiveDirectoryLdapAuthenticator(LdapContextSource contextSource, String domain) {
        super(contextSource);
        domain = StringUtils.hasText(domain) ? domain.toLowerCase(Locale.ROOT) : null;
        contextSource.setDomain(domain);
        contextSource.setupBaseEnv();
        if (domain != null) {
            setSearchBase(rootDnFromDomain(domain));
        }
    }

    @Override
    public DirContextAdapter authenticate(Authentication authentication) {
        assert authentication instanceof UsernamePasswordAuthenticationToken :
                "Support only UsernamePasswordAuthenticationToken objects";
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        if (!StringUtils.hasLength(password)) {
            throw new BadCredentialsException(
                    this.messages.getMessage("AbstractLdapAuthenticationProvider.emptyPassword", "Empty Password"));
        }
        DirContext ctx = null;
        try {
            ctx = bindUser(username, password);
            return searchForUser(ctx, username);
        } catch (NamingException e) {
            throw new BadCredentialsException(
                    this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception ex) {
                    log.debug("Closing LDAP context exception", ex);
                }
            }
        }
    }

    private DirContext bindUser(String username, String password) {
        String userPrincipal = createBindPrincipal(getContextSource(), username);
        log.trace("Attempting to bind as {}", userPrincipal);
        try {
            DirContext ctx = getContextSource().getContext(userPrincipal, password);
            log.debug("Bound {}", userPrincipal);
            return ctx;
        } catch (NamingException e) {
            log.trace("Failed to bind as {}", userPrincipal);
            throw new BadCredentialsException(
                    this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    }

    private DirContextAdapter searchForUser(DirContext ctx, String username) throws NamingException {
        log.trace("Searching for user {}", username);

        NamingEnumeration<SearchResult> resultsEnum = null;
        Set<SearchResult> results = new HashSet<>();
        try {
            LdapName searchBaseDn = LdapUtils.newLdapName(getSearchBase());

            SearchControls searchControls = buildControls();
            if (getUserAttributes() != null && getUserAttributes().length > 0) {
                searchControls.setReturningAttributes(getUserAttributes());
            }

            resultsEnum = ctx.search(searchBaseDn, getSearchFilter(), new String[]{username}, searchControls);
            log.trace("Searching for entry under base = {}, filter = {}",
                    searchBaseDn, getSearchFilter());

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
            throw e;
        }
        if (results.size() != 1) {
            if (results.isEmpty()) {
                throw new UsernameNotFoundException("User " + username + " not found in directory");
            }
            throw new BadCredentialsException("Result entries size must be 1. Actual: " + results.size());
        }
        SearchResult searchResult = results.iterator().next();
        return new DirContextAdapter(searchResult.getAttributes(), null, getContextSource().getBaseLdapName());
    }

    private String rootDnFromDomain(String domain) {
        String[] tokens = domain.split("\\.");
        List<String> rootDns = new ArrayList<>(tokens.length);
        for (String token : tokens) {
            rootDns.add("dc=" + token);
        }
        return String.join(",", rootDns);
    }

    private String createBindPrincipal(LdapContextSource contextSource, String username) {
        if (contextSource.getDomain() == null || username.toLowerCase(Locale.ROOT).endsWith(contextSource.getDomain())) {
            return username;
        }
        return username + "@" + contextSource.getDomain();
    }
}
