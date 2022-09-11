package ru.loolzaaa.authserver.config.security;

import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import ru.loolzaaa.authserver.config.security.bean.*;
import ru.loolzaaa.authserver.config.security.filter.ExternalLogoutFilter;
import ru.loolzaaa.authserver.config.security.filter.JwtTokenFilter;
import ru.loolzaaa.authserver.config.security.filter.LoginAccessFilter;
import ru.loolzaaa.authserver.config.security.property.BasicUsersProperties;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import java.util.List;

@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @RequiredArgsConstructor
    @EnableConfigurationProperties(BasicUsersProperties.class)
    @Order(1)
    @Configuration
    public static class BasicConfiguration extends WebSecurityConfigurerAdapter {

        private static final Logger log = LogManager.getLogger(BasicConfiguration.class.getName());

        private final BasicUsersProperties basicUsersProperties;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            if (basicUsersProperties.getUsers().size() == 0) {
                log.warn("\n\n\tThere is no basic users in properties. Some API unavailable!\n");
            }
            InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> usersConfigurer = auth.inMemoryAuthentication();
            for (BasicUsersProperties.BasicUser user : basicUsersProperties.getUsers()) {
                usersConfigurer
                        .withUser(user.getUsername())
                        .password(user.getPassword())
                        .authorities(basicUsersProperties.getBasicUserAuthority());
                log.info("Register basic user: {}", user.getUsername());
            }
            usersConfigurer
                    .withUser(basicUsersProperties.getRevokeUsername())
                    .password(basicUsersProperties.getRevokeUsername())
                    .authorities(basicUsersProperties.getRevokeAuthority());
            log.info("Register revoke token basic user: {}", basicUsersProperties.getRevokeUsername());
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            final String basicAntMatcherPattern = "/api/fast/**";
            final String basicPrepareLogoutMatcherPattern = "/api/fast/**";
            http
                    .antMatcher(basicPrepareLogoutMatcherPattern)
                    .csrf()
                        .disable()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                        .authorizeRequests()
                            .antMatchers(HttpMethod.POST, basicPrepareLogoutMatcherPattern)
                                .hasAuthority(basicUsersProperties.getRevokeAuthority())
                            .anyRequest()
                                .hasAuthority(basicUsersProperties.getBasicUserAuthority())
                    .and()
                        .httpBasic()
                            .realmName("Fast API");
            log.debug("Basic [{}] configuration completed", basicAntMatcherPattern);
            log.debug("JWT logout for other applications can be prepared via POST {} with '{}' authority",
                    basicPrepareLogoutMatcherPattern, basicUsersProperties.getRevokeAuthority());
            log.debug("All basic API can be accessed with '{}' authority", basicUsersProperties.getBasicUserAuthority());
        }
    }

    @RequiredArgsConstructor
    @EnableConfigurationProperties(SsoServerProperties.class)
    @Order(2)
    @Configuration
    public static class JwtConfiguration extends WebSecurityConfigurerAdapter {

        private static final Logger log = LogManager.getLogger(JwtConfiguration.class.getName());

        @Value("${spring.profiles.active:}")
        private String activeProfile;

        private final SsoServerProperties ssoServerProperties;

        private final PasswordEncoder passwordEncoder;

        private final UserDetailsService userDetailsService;

        private final JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;
        private final JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler;
        private final JwtLogoutHandler jwtLogoutHandler;

        private final AnonymousAuthenticationHandler anonymousAuthenticationHandler;

        private final JWTService jwtService;
        private final CookieService cookieService;
        private final SecurityContextService securityContextService;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(authenticationProvider());

            // Set current application name from properties for request authorizing
            //UserPrincipal.setApplicationName(applicationName);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf()
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .and()
                    .cors()
                    .and()
                        .sessionManagement()
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                        .authorizeRequests()
                            .antMatchers("/actuator/**")
                                .hasRole("ADMIN")
                            .antMatchers(anonymousAuthenticationHandler.toAntPatterns())
                                .anonymous()
                            .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                                .anonymous()
                            .anyRequest()
                                .hasAuthority(ssoServerProperties.getApplication().getName())
                    .and()
                        .formLogin()
                            .loginPage(ssoServerProperties.getLoginPage())
                            .loginProcessingUrl("/do_login")
                            .failureHandler(jwtAuthenticationFailureHandler)
                            .successHandler(jwtAuthenticationSuccessHandler)
                            .permitAll()
                    .and()
                        .logout()
                            .logoutRequestMatcher(new AntPathRequestMatcher("/do_logout", "POST"))
                            .logoutSuccessUrl(ssoServerProperties.getLoginPage() + "?successLogout")
                            .addLogoutHandler(jwtLogoutHandler)
                            .deleteCookies("JSESSIONID", CookieName.ACCESS.getName(), CookieName.REFRESH.getName(), CookieName.RFID.getName())
                            .invalidateHttpSession(true)
                            .clearAuthentication(true)
                            .permitAll()
                    .and()
                        .httpBasic()
                            .disable()
                    // Filters order is important!
                    .addFilterBefore(new ExternalLogoutFilter(securityContextService, jwtService), UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(new JwtTokenFilter(ssoServerProperties.getRefreshUri(), anonymousAuthenticationHandler,
                                    securityContextService, jwtService, cookieService), UsernamePasswordAuthenticationFilter.class)
                    .addFilterAfter(new LoginAccessFilter(ssoServerProperties.getLoginPage()), UsernamePasswordAuthenticationFilter.class);
            log.debug("Jwt [all API except Basic authentication] configuration completed");
        }

        @Override
        public void configure(WebSecurity web) {
            if (activeProfile.contains("dev")) {
                web.ignoring().antMatchers("/h2-console/**");
            }
        }

        @Bean
        AuthenticationProvider authenticationProvider() {
            CustomDaoAuthenticationProvider authenticationProvider = new CustomDaoAuthenticationProvider();
            authenticationProvider.setPasswordEncoder(passwordEncoder);
            authenticationProvider.setUserDetailsService(userDetailsService);
            return authenticationProvider;
        }
    }

    @Profile("prod")
    @Bean
    PasswordEncoder passwordEncoder() {
        return new CustomPBKDF2PasswordEncoder();
    }

    @Profile("dev")
    @Bean
    PasswordEncoder noopPasswordEncoder() {
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
