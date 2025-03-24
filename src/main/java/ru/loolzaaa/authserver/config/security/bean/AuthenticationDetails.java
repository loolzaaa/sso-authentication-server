package ru.loolzaaa.authserver.config.security.bean;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.io.Serializable;
import java.util.Objects;

@ToString
@Getter
public class AuthenticationDetails implements Serializable {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String remoteAddress;

    private final String authenticationMode;

    public AuthenticationDetails(HttpServletRequest request) {
        this.remoteAddress = request.getRemoteAddr();
        this.authenticationMode = request.getParameter("_authenticationMode");
    }

    public AuthenticationDetails(String authenticationMode) {
        this.remoteAddress = null;
        this.authenticationMode = authenticationMode;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationDetails that = (AuthenticationDetails) o;
        return Objects.equals(getRemoteAddress(), that.getRemoteAddress()) && Objects.equals(getAuthenticationMode(), that.getAuthenticationMode());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRemoteAddress(), getAuthenticationMode());
    }
}
