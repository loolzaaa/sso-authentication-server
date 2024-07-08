package ru.loolzaaa.authserver.config.security.bean;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import ru.loolzaaa.authserver.model.UserPrincipal;

public class CustomDaoAuthenticationProvider extends DaoAuthenticationProvider {
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
