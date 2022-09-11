package ru.loolzaaa.authserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

@RequiredArgsConstructor
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final SsoServerProperties ssoServerProperties;

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");
        registry.addViewController(ssoServerProperties.getLoginPage()).setViewName("login");
        registry.addViewController(ssoServerProperties.getRefreshUri()).setViewName("trefresh");
    }
}
