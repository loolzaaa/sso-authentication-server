package ru.loolzaaa.authserver.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

public final class WithUserDetailsSecurityContextFactory implements WithSecurityContextFactory<WithMockJwtUser> {

    private final UserDetailsService userDetailsService;

    @Autowired
    public WithUserDetailsSecurityContextFactory(@Qualifier("jwtUserDetailsService") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public SecurityContext createSecurityContext(WithMockJwtUser withUser) {
        String username = withUser.username();
        UserDetails principal = userDetailsService.loadUserByUsername(username);
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
