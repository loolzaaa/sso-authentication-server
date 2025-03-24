package ru.loolzaaa.authserver.config.security.bean;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import ru.loolzaaa.authserver.ldap.DirContextAdapter;
import ru.loolzaaa.authserver.ldap.LdapAuthenticator;

public class LdapAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LogManager.getLogger(LdapAuthenticationProvider.class);

    private static final String AUTHENTICATION_MODE = "ldap";

    private final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Getter
    @Setter
    private LdapAuthenticator authenticator;

    @Getter
    @Setter
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
                () -> this.messages.getMessage("LdapAuthenticationProvider.onlySupports",
                        "Only UsernamePasswordAuthenticationToken is supported"));
        UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken) authentication;
        String authenticationMode = ((AuthenticationDetails) userToken.getDetails()).getAuthenticationMode();
        if (!AUTHENTICATION_MODE.equalsIgnoreCase(authenticationMode)) {
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        String username = userToken.getName();
        String password = (String) authentication.getCredentials();
        if (!StringUtils.hasLength(username)) {
            throw new BadCredentialsException(
                    this.messages.getMessage("LdapAuthenticationProvider.emptyUsername", "Empty Username"));
        }
        if (!StringUtils.hasLength(password)) {
            throw new BadCredentialsException(
                    this.messages.getMessage("AbstractLdapAuthenticationProvider.emptyPassword", "Empty Password"));
        }
        Assert.notNull(password, "Null password was supplied in authentication token");
        DirContextAdapter userData = authenticator.authenticate(authentication);
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) {
            log.debug("Failed to find user '" + username + "'");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
        UsernamePasswordAuthenticationToken result = UsernamePasswordAuthenticationToken.authenticated(
                user,
                authentication.getCredentials(),
                user.getAuthorities());
        result.setDetails(authentication.getDetails());
        log.debug("Authenticated user");
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
