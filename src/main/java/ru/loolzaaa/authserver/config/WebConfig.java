package ru.loolzaaa.authserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.util.Locale;

@RequiredArgsConstructor
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private static final String FORBIDDEN_PATH = "/forbidden";
    private static final String ADMIN_PANEL_PATH = "/admin";

    private final SsoServerProperties ssoServerProperties;

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController(FORBIDDEN_PATH).setViewName("403");
        registry.addViewController(ADMIN_PANEL_PATH).setViewName("admin");
        registry.addViewController(ssoServerProperties.getLoginPage()).setViewName("login");
        registry.addViewController(ssoServerProperties.getRefreshUri()).setViewName("trefresh");
    }

    @Bean
    LocaleResolver localeResolver() {
        AcceptHeaderLocaleResolver localeResolver = new AcceptHeaderLocaleResolver();
        localeResolver.setDefaultLocale(Locale.US);
        return localeResolver;
    }

    @Bean
    AccessDeniedHandler accessDeniedHandler() {
        AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
        accessDeniedHandler.setErrorPage(FORBIDDEN_PATH);
        return accessDeniedHandler;
    }
}
