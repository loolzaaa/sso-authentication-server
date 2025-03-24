package ru.loolzaaa.authserver.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import ru.loolzaaa.authserver.config.security.bean.CustomDaoAuthenticationProvider;
import ru.loolzaaa.authserver.config.security.bean.CustomPBKDF2PasswordEncoder;
import ru.loolzaaa.authserver.config.security.bean.NoopCustomPasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@EnableMethodSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig implements WebSecurityCustomizer {

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    @Override
    public void customize(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        if (activeProfile.contains("h2")) {
            web.ignoring().antMatchers("/h2-console/**");
        }
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> authenticationProviders) {
        AuthenticationProvider firstProvider = null;
        List<AuthenticationProvider> orderedProviders = new ArrayList<>(authenticationProviders.size());
        for (AuthenticationProvider provider : authenticationProviders) {
            if (provider instanceof CustomDaoAuthenticationProvider) {
                firstProvider = provider;
                continue;
            }
            orderedProviders.add(provider);
        }
        if (firstProvider != null) {
            orderedProviders.add(0, firstProvider);
        }
        return new ProviderManager(orderedProviders);
    }

    @Profile("!noop")
    @Qualifier("jwtPasswordEncoder")
    @Bean
    public PasswordEncoder jwtPasswordEncoder() {
        return new CustomPBKDF2PasswordEncoder();
    }

    @Primary
    @Qualifier("basicPasswordEncoder")
    @Bean
    public PasswordEncoder basicPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Profile("noop")
    @Qualifier("jwtPasswordEncoder")
    @Bean
    public PasswordEncoder noopPasswordEncoder() {
        return new NoopCustomPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(List.of("http://localhost:[*]"));
        config.setAllowedMethods(List.of("GET", "HEAD", "POST", "PATCH"));
        config.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
