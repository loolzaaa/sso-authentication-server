package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import ru.loolzaaa.authserver.model.UserPrincipal;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class})
class CustomDaoAuthenticationProviderTest {

    final String hash = "HASH";

    @Mock
    UserPrincipal userDetails;
    @Mock
    UsernamePasswordAuthenticationToken authentication;

    @Mock
    CustomPBKDF2PasswordEncoder passwordEncoder;

    CustomDaoAuthenticationProvider authenticationProvider;

    @BeforeEach
    void setUp() {
        authenticationProvider = new CustomDaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        when(authentication.getCredentials()).thenReturn(hash);
    }

    @Test
    void shouldThrowExceptionIfCredentialIsNull() {
        when(authentication.getCredentials()).thenReturn(null);

        assertThatThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(userDetails, authentication))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void shouldThrowExceptionIfPasswordEncoderIsNotSupported() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        authenticationProvider.setPasswordEncoder(bCryptPasswordEncoder);

        assertThatThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(userDetails, authentication))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported password encoder");
    }

    @Test
    void shouldThrowExceptionIfUserDetailsIsNotSupported() {
        UserDetails mockUserDetails = mock(UserDetails.class);

        assertThatThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(mockUserDetails, authentication))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported user details implementation");
    }

    @Test
    void shouldThrowExceptionIfCredentialsIsInvalid() {
        assertThatThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(userDetails, authentication))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void shouldPassIfCredentialsIsValid() {
        final String SALT = "SALT";
        when(userDetails.getHashes()).thenReturn(List.of(hash));
        when(userDetails.getSalt()).thenReturn(SALT);
        when(passwordEncoder.matches(any(), anyString())).thenReturn(true);

        authenticationProvider.additionalAuthenticationChecks(userDetails, authentication);

        verify(passwordEncoder).setSalt(SALT);
        verify(passwordEncoder).setSalt(null);
    }
}