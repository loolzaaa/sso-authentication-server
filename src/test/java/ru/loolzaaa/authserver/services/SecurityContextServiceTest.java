package ru.loolzaaa.authserver.services;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;

import java.util.Collection;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityContextServiceTest {

    final String login = "LOGIN";

    @Mock
    UserRepository userRepository;

    @Mock
    CookieService cookieService;
    @Mock
    JWTService jwtService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;

    SecurityContextService securityContextService;

    @BeforeEach
    void setUp() {
        securityContextService = new SecurityContextService(userRepository, cookieService, jwtService);
    }

    @Test
    void shouldUpdateSecurityContextIfUserExist() {
        User user = mock(User.class);
        ReflectionTestUtils.setField(user, "login", login);
        when(userRepository.findByLogin(login)).thenReturn(Optional.of(user));

        securityContextService.updateSecurityContextHolder(req, login);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication)
                .isNotNull()
                .isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getCredentials()).isNull();
        assertThat(authentication.getPrincipal())
                .isNotNull()
                .isInstanceOf(UserPrincipal.class)
                .extracting(o -> ((UserPrincipal)o).getUser())
                    .isNotNull()
                    .isEqualTo(user);
        final UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        assertThat(authorities)
                .isNotNull()
                .hasSize(principal.getAuthorities().size());
                //.hasSameElementsAs(principal.getAuthorities())
    }

    @Test
    void throwExceptionIfUserNotFound() {
        when(userRepository.findByLogin(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> securityContextService.updateSecurityContextHolder(req, login))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void shouldClearSecurityContextAndInvalidateSessionAndRemoveCookie() {
        final String TOKEN = "TOKEN";
        final HttpSession httpSession = mock(HttpSession.class);
        final ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        when(req.getSession(anyBoolean())).thenReturn(httpSession);
        when(cookieService.getCookieValueByName(anyString(), any())).thenReturn(TOKEN);

        securityContextService.clearSecurityContextHolder(req, resp);

        verify(httpSession).invalidate();
        verify(jwtService).deleteTokenFromDatabase(tokenCaptor.capture());
        verify(cookieService).clearCookies(req, resp);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(tokenCaptor.getValue()).isEqualTo(TOKEN);
    }
}