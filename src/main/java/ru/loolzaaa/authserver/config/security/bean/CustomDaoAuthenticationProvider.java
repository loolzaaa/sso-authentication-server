package ru.loolzaaa.authserver.config.security.bean;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;
import ru.loolzaaa.authserver.model.UserPrincipal;

public class CustomDaoAuthenticationProvider extends DaoAuthenticationProvider {

    public static final String AUTHENTICATION_MODE = "sso";

    @Override
    protected void doAfterPropertiesSet() {
        super.doAfterPropertiesSet();
        this.messages = SpringSecurityMessageSource.getAccessor();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
                () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only UsernamePasswordAuthenticationToken is supported"));
        UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken) authentication;
        String authenticationMode = ((AuthenticationDetails) userToken.getDetails()).getAuthenticationMode();
        if (!AUTHENTICATION_MODE.equalsIgnoreCase(authenticationMode)) {
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        return super.authenticate(authentication);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            this.logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        } else {
            String presentedPassword = authentication.getCredentials().toString();
            if (!matchPasswords(presentedPassword, userDetails)) {
                this.logger.debug("Failed to authenticate since password does not match stored value");
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }
        }
    }

    private boolean matchPasswords(String presentedPassword, UserDetails userDetails) {
        if (this.getPasswordEncoder() instanceof CustomPBKDF2PasswordEncoder passwordEncoder) {
            if (userDetails instanceof UserPrincipal user) {
                passwordEncoder.setSalt(user.getSalt());
                boolean matchResult = user.getHashes()
                        .stream()
                        .anyMatch(hash -> passwordEncoder.matches(presentedPassword, hash));
                passwordEncoder.setSalt(null);
                return matchResult;
            } else {
                throw new IllegalArgumentException("Unsupported user details implementation");
            }
        } else {
            throw new IllegalArgumentException("Unsupported password encoder");
        }
    }
}
