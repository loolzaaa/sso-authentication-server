package ru.loolzaaa.authserver.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.repositories.UserRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    JdbcTemplate jdbcTemplate;

    @Mock
    UserRepository userRepository;

    @Mock
    User user;

    UserServiceImpl userService;

    @BeforeEach
    void setUp() {
        userService = new UserServiceImpl(userRepository, jdbcTemplate);
    }

    @Test
    void shouldThrowExceptionIfUserNotExist() {
        when(userRepository.findByLogin(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.loadUserByUsername("invalid"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void shouldReturnUserDetailsWithoutHashes() {
        when(userRepository.findByLogin(anyString())).thenReturn(Optional.of(user));
        when(user.isEnabled()).thenReturn(false);

        UserDetails userDetails = userService.loadUserByUsername("valid");

        verifyNoInteractions(jdbcTemplate);
        assertNotNull(userDetails);
    }

    @Test
    void shouldReturnUserDetailsWithHashes() {
        when(userRepository.findByLogin(anyString())).thenReturn(Optional.of(user));
        when(user.isEnabled()).thenReturn(true);

        UserDetails userDetails = userService.loadUserByUsername("valid");

        verify(jdbcTemplate).queryForList(anyString(), eq(String.class));
        verify(user).getHashes();
        assertNotNull(userDetails);
    }
}