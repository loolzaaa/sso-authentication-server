package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.util.List;

@RequiredArgsConstructor
@Component
public class AnonymousAuthenticationHandler {

    private final SsoServerProperties ssoServerProperties;

    private final List<String> anonymousPatterns = List.of("/api/refresh", "/api/refresh/ajax");

    public boolean checkUri(String uri) {
        if (uri == null) {
            return false;
        }
        if (uri.toLowerCase().startsWith(ssoServerProperties.getRefreshUri())) {
            return true;
        }
        for (String pattern : anonymousPatterns) {
            if (uri.toLowerCase().startsWith(pattern)) {
                return true;
            }
        }
        return false;
    }

    public String[] toAntPatterns() {
        return new String[]{ ssoServerProperties.getRefreshUri(), anonymousPatterns.get(0), anonymousPatterns.get(1)};
    }
}
