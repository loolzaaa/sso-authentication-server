package ru.loolzaaa.authserver.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;


@Log4j2
public class UserPrincipal implements UserDetails {

    private static String applicationName;

    @Getter
    private final User user;

    private final List<GrantedAuthority> authorities = new ArrayList<>();

    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;

    // For authentication and authorization in this application
    public UserPrincipal(User user) {
        this.user = user;

        JsonNode userConf = user.getJsonConfig();
        if (userConf == null) {
            log.warn("User [{}] does not contain config", user.getLogin());
            this.accountNonLocked = false;
            return;
        }

        userConf.fieldNames().forEachRemaining(s -> authorities.add(new SimpleGrantedAuthority(s)));
        if (!userConf.has(applicationName)) {
            log.info("User [{}] is locked", user.getLogin());
            this.accountNonLocked = false;
            return;
        }

        JsonNode authNode = userConf.get(applicationName);
        if (authNode.has(UserAttributes.ROLES)) {
            authNode.get(UserAttributes.ROLES).forEach(role -> this.authorities.add(new SimpleGrantedAuthority(role.asText())));
        }
        if (authNode.has(UserAttributes.CREDENTIALS_EXP) && isUserCredentialsExpired(authNode)) {
            log.info("User [{}] credentials is expired", user.getLogin());
            this.credentialsNonExpired = false;
        }
        if (authNode.has(UserAttributes.LOCK)) {
            this.accountNonLocked = !authNode.get(UserAttributes.LOCK).asBoolean();
        }

        //check for date access for temporary user
        if (authNode.has(UserAttributes.TEMPORARY)) {
            ((ObjectNode) authNode.get(UserAttributes.TEMPORARY)).remove("pass");
            LocalDate dateFrom = LocalDate.parse(authNode.get(UserAttributes.TEMPORARY).get("dateFrom").asText());
            LocalDate dateTo = LocalDate.parse(authNode.get(UserAttributes.TEMPORARY).get("dateTo").asText());
            if (dateFrom.isAfter(LocalDate.now()) || dateTo.isBefore(LocalDate.now())) {
                log.info("User [{}] temporary account is expired", user.getLogin());
                this.accountNonExpired = false;
            }
        }
    }

    // For authentication and authorization in other applications
    public UserPrincipal(User user, String app) {
        this(user);

        JsonNode userConf = user.getJsonConfig();
        if (userConf == null) {
            throw new IllegalArgumentException(String.format("There is no config for user [%s]", this.user.getLogin()));
        }
        if (app == null) {
            return;
        }
        JsonNode appConfig = userConf.get(app);
        if (appConfig == null) {
            throw new IllegalArgumentException(String.format("There is no application [%s] for user [%s]", app, this.user.getLogin()));
        }
        this.authorities.removeIf(grantedAuthority -> !app.equals(grantedAuthority.getAuthority()));
        if (appConfig.has(UserAttributes.ROLES)) {
            appConfig.get(UserAttributes.ROLES).forEach(role -> this.authorities.add(new SimpleGrantedAuthority(role.asText())));
        }
        if (appConfig.has(UserAttributes.PRIVILEGES)) {
            appConfig.get(UserAttributes.PRIVILEGES).forEach(privilege -> this.authorities.add(new SimpleGrantedAuthority(privilege.asText())));
        }
        ((ObjectNode) appConfig).remove(List.of(UserAttributes.ROLES, UserAttributes.PRIVILEGES));
        if (userConf.get(applicationName).has(UserAttributes.TEMPORARY)) {
            JsonNode temporaryNode = userConf.get(applicationName).get(UserAttributes.TEMPORARY);
            ((ObjectNode) appConfig).set(UserAttributes.TEMPORARY, temporaryNode);
        }
        user.setConfig(new UserConfigWrapper(appConfig));
    }

    public static void setApplicationName(String applicationName) {
        UserPrincipal.applicationName = applicationName;
    }

    @JsonIgnore
    public Long getId() {
        return user.getId();
    }

    @JsonIgnore
    public String getSalt() {
        return user.getSalt();
    }

    @JsonIgnore
    public List<String> getHashes() {
        return user.getHashes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        throw new UnsupportedOperationException("This implementation of UserDetails does not support this method");
    }

    @JsonIgnore
    @Override
    public String getUsername() {
        return user.getLogin();
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserPrincipal that = (UserPrincipal) o;
        return Objects.equals(user, that.user);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user);
    }

    private boolean isUserCredentialsExpired(JsonNode authNode) {
        return Instant.ofEpochMilli(authNode.get(UserAttributes.CREDENTIALS_EXP).asLong()).isBefore(Instant.now());
    }
}
