package ru.loolzaaa.authserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value("${auth.refresh.token.uri}")
    private String refreshTokenURI;
    @Value("${auth.main.login.page}")
    private String mainLoginPage;

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");
        registry.addViewController(mainLoginPage).setViewName("login");
        registry.addViewController(refreshTokenURI).setViewName("trefresh");
    }
}
