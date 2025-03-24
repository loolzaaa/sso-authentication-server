package ru.loolzaaa.authserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.function.RenderingResponse;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import ru.loolzaaa.authserver.config.security.property.LdapServerProperties;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.util.Locale;

import static org.springframework.web.servlet.function.RenderingResponse.*;
import static org.springframework.web.servlet.function.RouterFunctions.*;

@RequiredArgsConstructor
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final SsoServerProperties ssoServerProperties;
    private final LdapServerProperties ldapServerProperties;

    @Bean
    public RouterFunction<ServerResponse> login() {
        RenderingResponse response = create("login")
                .modelAttribute("ldapEnabled", ldapServerProperties.isEnabled())
                .build();
        return route().GET(ssoServerProperties.getLoginPage(), req -> response).build();
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController(ssoServerProperties.getForbiddenUri()).setViewName("403");
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
