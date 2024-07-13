package ru.loolzaaa.authserver.config.security;

import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import ru.loolzaaa.authserver.config.security.property.BasicUsersProperties;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@RequiredArgsConstructor
@EnableConfigurationProperties(BasicUsersProperties.class)
@Configuration
public class BasicSecurityConfig {

    private static final Logger log = LogManager.getLogger(BasicSecurityConfig.class.getName());

    private final BasicUsersProperties basicUsersProperties;

    @Qualifier("basicPasswordEncoder")
    private final PasswordEncoder passwordEncoder;

    @Bean("basicUserDetailsService")
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        if (basicUsersProperties.getUsers().isEmpty()) {
            log.warn("\n\n\tThere is no basic users in properties. Some API unavailable!\n");
        }
        List<UserDetails> userDetailsList = new ArrayList<>(basicUsersProperties.getUsers().size() + 2);
        for (BasicUsersProperties.BasicUser user : basicUsersProperties.getUsers()) {
            userDetailsList.add(User
                    .withUsername(user.getUsername())
                    .password(passwordEncoder.encode(user.getPassword()))
                    .authorities(basicUsersProperties.getBasicUserAuthority())
                    .build());
            log.info("Register basic user: {}", user.getUsername());
        }
        userDetailsList.add(User
                .withUsername(basicUsersProperties.getRevokeUsername())
                .password(passwordEncoder.encode(basicUsersProperties.getRevokePassword()))
                .authorities(basicUsersProperties.getRevokeAuthority())
                .build());
        log.info("Register revoke token basic user: {}", basicUsersProperties.getRevokeUsername());
        if (basicUsersProperties.isActuatorEnable()) {
            userDetailsList.add(User
                    .withUsername(basicUsersProperties.getActuatorUsername())
                    .password(passwordEncoder.encode(basicUsersProperties.getActuatorPassword()))
                    .authorities("ROLE_" + basicUsersProperties.getActuatorAuthority())
                    .build());
            log.info("Register actuator admin user: {}", basicUsersProperties.getActuatorUsername());
        }
        return new InMemoryUserDetailsManager(userDetailsList);
    }

    @Order(1)
    @Bean
    public SecurityFilterChain basicFilterChain(HttpSecurity http) throws Exception {
        final String basicMvcMatcherPattern = "/api/fast/**";
        final String basicPrepareLogoutMatcherPattern = "/api/fast/prepare_logout";
        http
                .userDetailsService(inMemoryUserDetailsManager())
                .securityMatcher(basicMvcMatcherPattern)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, basicPrepareLogoutMatcherPattern).hasAuthority(basicUsersProperties.getRevokeAuthority())
                        .requestMatchers(HttpMethod.POST, "/api/fast/rfid").permitAll()
                        .anyRequest().hasAuthority(basicUsersProperties.getBasicUserAuthority()))
                .httpBasic(httpBasic -> httpBasic
                        .realmName("Fast API"))
                .anonymous(AbstractHttpConfigurer::disable);
        log.debug("Basic [{}] configuration completed", basicMvcMatcherPattern);
        log.debug("JWT logout for other applications can be prepared via POST {} with '{}' authority",
                basicPrepareLogoutMatcherPattern, basicUsersProperties.getRevokeAuthority());
        log.debug("All basic API can be accessed with '{}' authority", basicUsersProperties.getBasicUserAuthority());
        return http.build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
        http
                .userDetailsService(inMemoryUserDetailsManager())
                .securityMatcher(EndpointRequest.toAnyEndpoint())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().hasRole(basicUsersProperties.getActuatorAuthority()))
                .httpBasic(withDefaults());
        log.debug("Actuator [{}] configuration completed", EndpointRequest.toAnyEndpoint());
        log.debug("All actuator API can be accessed with '{}' role", basicUsersProperties.getActuatorAuthority());
        return http.build();
    }
}
