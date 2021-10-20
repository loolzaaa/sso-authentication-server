package ru.loolzaaa.authserver.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import ru.loolzaaa.authserver.config.security.bean.*;
import ru.loolzaaa.authserver.config.security.filter.JwtTokenFilter;
import ru.loolzaaa.authserver.config.security.filter.LoginAccessFilter;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.services.CookieService;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import java.util.List;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig {

    @RequiredArgsConstructor
    @Order(1)
    @Configuration
    public static class BasicConfiguration extends WebSecurityConfigurerAdapter {

        @Value("${auth.basic.login}")
        private String basicLogin;
        @Value("${auth.basic.password}")
        private String basicPassword;
        @Value("${auth.basic.authority}")
        private String basicAuthority;

        @Value("${auth.basic.external.login}")
        private String basicExternalLogin;
        @Value("${auth.basic.external.password}")
        private String basicExternalPassword;

        private final PasswordEncoder passwordEncoder;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                        .withUser(basicLogin)
                            .password(passwordEncoder.encode(basicPassword))
                            .authorities(basicAuthority)
                    .and()
                        .withUser(basicExternalLogin)
                            .password(passwordEncoder.encode(basicExternalPassword))
                            .authorities(basicAuthority);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher("/api/fast/**")
                    .csrf()
                        .disable()
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                        .authorizeRequests()
                        .anyRequest()
                            .hasAuthority(basicAuthority)
                    .and()
                        .httpBasic()
                            .realmName("Fast API");
        }
    }

    @RequiredArgsConstructor
    @Order(2)
    @Configuration
    public static class WebConfiguration extends WebSecurityConfigurerAdapter {

        @Value("${spring.profiles.active:}")
        private String activeProfile;
        @Value("${auth.application.name}")
        private String applicationName;
        @Value("${auth.refresh.token.uri}")
        private String refreshTokenURI;
        @Value("${auth.main.login.page}")
        private String mainLoginPage;

        private final PasswordEncoder passwordEncoder;

        private final UserDetailsService userDetailsService;

        private final JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;
        private final JwtAuthenticationFailureHandler jwtAuthenticationFailureHandler;
        private final JwtLogoutHandler jwtLogoutHandler;

        private final JWTService jwtService;
        private final CookieService cookieService;
        private final SecurityContextService securityContextService;

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(authenticationProvider());

            // Set current application name from properties for request authorizing
            UserPrincipal.setApplicationName(applicationName);
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
                            .anyRequest()
                                .hasAuthority(applicationName)
                    .and()
                        .formLogin()
                            .loginPage(mainLoginPage)
                            .loginProcessingUrl("/do_login")
                            .failureHandler(jwtAuthenticationFailureHandler)
                            .successHandler(jwtAuthenticationSuccessHandler)
                            .permitAll()
                    .and()
                        .logout()
                            .logoutRequestMatcher(new AntPathRequestMatcher("/do_logout", "POST"))
                            .logoutSuccessUrl(mainLoginPage + "?successLogout")
                            .addLogoutHandler(jwtLogoutHandler)
                            .deleteCookies("JSESSIONID", "_t_access", "_t_refresh", "_t_rfid")
                            .invalidateHttpSession(true)
                            .clearAuthentication(true)
                            .permitAll()
                    .and()
                        .httpBasic()
                            .disable()
                    .addFilterBefore(new JwtTokenFilter(refreshTokenURI, securityContextService, jwtService, cookieService),
                            UsernamePasswordAuthenticationFilter.class)
                    .addFilterAfter(new LoginAccessFilter(mainLoginPage), UsernamePasswordAuthenticationFilter.class);
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web
                    .ignoring()
                        .antMatchers("/webjars/**", "/js/**", "/css/**", "/images/**", "/favicon.*")
                        .antMatchers(refreshTokenURI, "/api/refresh", "/api/refresh/ajax");

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

    @Bean
    PasswordEncoder passwordEncoder() {
        return new CustomPBKDF2PasswordEncoder();
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(List.of("http://localhost:[*]"));
        config.setAllowedMethods(List.of("GET", "HEAD", "POST"));
        config.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
