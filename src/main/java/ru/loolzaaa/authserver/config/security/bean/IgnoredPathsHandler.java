package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;

import java.util.List;

@RequiredArgsConstructor
@Component
public class IgnoredPathsHandler {

    private final SsoServerProperties ssoServerProperties;

    private final List<String> ignoredPatterns = List.of("/api/refresh", "/api/refresh/ajax");

    public boolean checkUri(String uri) {
        if (uri == null) {
            return false;
        }
        if (uri.toLowerCase().startsWith(ssoServerProperties.getRefreshUri())) {
            return true;
        }
        for (String pattern : ignoredPatterns) {
            if (uri.toLowerCase().startsWith(pattern)) {
                return true;
            }
        }
        return false;
    }

    public String[] toMvcPatterns() {
        return new String[]{ ssoServerProperties.getRefreshUri(), ignoredPatterns.get(0), ignoredPatterns.get(1)};
    }
}
