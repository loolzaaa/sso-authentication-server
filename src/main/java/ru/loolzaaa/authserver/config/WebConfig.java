package ru.loolzaaa.authserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import ru.loolzaaa.authserver.config.security.property.LdapServerProperties;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.net.URI;
import java.util.Locale;

import static org.springframework.web.servlet.function.RenderingResponse.*;
import static org.springframework.web.servlet.function.RouterFunctions.*;
import static org.springframework.web.servlet.function.ServerResponse.*;

@RequiredArgsConstructor
@Configuration
public class WebConfig implements WebMvcConfigurer {

    public static final String ALREADY_LOGGED_IN_ATTRIBUTE = "ALREADY_LOGGED_IN";

    private final SsoServerProperties ssoServerProperties;
    private final LdapServerProperties ldapServerProperties;

    @Bean
    public RouterFunction<ServerResponse> login() {
        HandlerFunction<ServerResponse> handler = request -> {
            boolean hasAlreadyLoggedInAttribute = (boolean) request.attribute(ALREADY_LOGGED_IN_ATTRIBUTE).orElse(false);
            if (hasAlreadyLoggedInAttribute) {
                String contextPath = request.requestPath().contextPath().value();
                if (!contextPath.endsWith("/")) {
                    contextPath += "/";
                }
                return temporaryRedirect(URI.create(contextPath)).build();
            }
            return create("login")
                    .modelAttribute("ldapEnabled", ldapServerProperties.isEnabled())
                    .build();
        };
        return route().GET(ssoServerProperties.getLoginPage(), handler).build();
    }

    @Bean
    public RouterFunction<ServerResponse> forbidden() {
        return route()
                .route(RequestPredicates.path(ssoServerProperties.getForbiddenUri()),
                        request -> create("403").status(HttpStatus.FORBIDDEN).build())
                .build();
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController(ssoServerProperties.getAdminUri()).setViewName("admin");
        registry.addViewController(ssoServerProperties.getRefreshUri()).setViewName("trefresh");
    }

    @Bean
    public LocaleResolver localeResolver() {
        AcceptHeaderLocaleResolver localeResolver = new AcceptHeaderLocaleResolver();
        localeResolver.setDefaultLocale(createServerLocale());
        return localeResolver;
    }

    @Bean
    public FilterRegistrationBean<MdcLoggingFilter> mdcLoggingFilter() {
        FilterRegistrationBean<MdcLoggingFilter> registration = new FilterRegistrationBean<>(new MdcLoggingFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<MdcUsernameFilter> mdcUsernameFilter() {
        FilterRegistrationBean<MdcUsernameFilter> registration = new FilterRegistrationBean<>(new MdcUsernameFilter());
        // Run after the Spring Security filter chain (-100), once the user is authenticated
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER + 1);
        return registration;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(ssoServerProperties.getForbiddenUri());
        return accessDeniedHandler;
    }

    private Locale createServerLocale() {
        return switch (ssoServerProperties.getLanguage()) {
            case "ru" -> new Locale("ru");
            default -> new Locale("en");
        };
    }
}
