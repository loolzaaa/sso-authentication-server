package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ru.loolzaaa.authserver.ldap.LdapAuthenticator;

import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LdapAuthenticationProviderTest {

    @Mock
    UsernamePasswordAuthenticationToken token;

    @Mock
    LdapAuthenticator authenticator;
    @Mock
    UserDetailsService userDetailsService;

    LdapAuthenticationProvider authenticationProvider;

    @BeforeEach
    void setUp() {
        authenticationProvider = new LdapAuthenticationProvider();
        authenticationProvider.setAuthenticator(authenticator);
        authenticationProvider.setUserDetailsService(userDetailsService);
    }

    @Test
    public void shouldThrowExceptionIfTokenTypeIncorrect() {
        assertThatThrownBy(() -> authenticationProvider.authenticate(
                new TestingAuthenticationToken(null, null)));
    }

    @Test
    public void shouldThrowExceptionIfIncorrectAuthenticationMode() {
        AuthenticationDetails details = new AuthenticationDetails("test");
        when(token.getDetails()).thenReturn(details);

        assertThatThrownBy(() -> authenticationProvider.authenticate(token));
    }

    @Test
    public void shouldThrowExceptionIfCredentialsEmpty() {
        AuthenticationDetails details = new AuthenticationDetails("ldap");
        when(token.getDetails()).thenReturn(details);
        when(token.getName()).thenReturn("");

        assertThatThrownBy(() -> authenticationProvider.authenticate(token));

        when(token.getName()).thenReturn("user");
        when(token.getCredentials()).thenReturn("");

        assertThatThrownBy(() -> authenticationProvider.authenticate(token));
    }

    @Test
    public void shouldThrowExceptionIfUserNotFound() {
        AuthenticationDetails details = new AuthenticationDetails("ldap");
        when(token.getDetails()).thenReturn(details);
        when(token.getName()).thenReturn("user");
        when(token.getCredentials()).thenReturn("pass");
        when(authenticator.authenticate(any())).thenReturn(null);
        when(userDetailsService.loadUserByUsername(anyString())).thenThrow(UsernameNotFoundException.class);

        assertThatThrownBy(() -> authenticationProvider.authenticate(token));
    }

    @Test
    public void shouldReturnAuthenticatedTokenIfAllCorrect() {
        AuthenticationDetails details = new AuthenticationDetails("ldap");
        when(token.getDetails()).thenReturn(details);
        when(token.getName()).thenReturn("user");
        when(token.getCredentials()).thenReturn("pass");
        when(authenticator.authenticate(any())).thenReturn(null);
        when(userDetailsService.loadUserByUsername(anyString()))
                .thenReturn(new User("user", "test", List.of()));

        Authentication authenticate = authenticationProvider.authenticate(token);

        assertThat(authenticate.isAuthenticated()).isTrue();
    }
}