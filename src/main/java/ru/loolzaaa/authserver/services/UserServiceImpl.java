package ru.loolzaaa.authserver.services;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;

import java.util.List;

@RequiredArgsConstructor
@Service
@Qualifier("jwtUserDetailsService")
public class UserServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    private final JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByLogin(username).orElse(null);

        if (user != null) {
            if (user.isEnabled()) {
                List<String> hashes = jdbcTemplate.queryForList("SELECT * FROM hashes", String.class);
                user.getHashes().addAll(hashes);
            }

            return new UserPrincipal(user);
        } else {
            throw new UsernameNotFoundException(username);
        }
    }
}
