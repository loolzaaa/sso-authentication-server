package ru.loolzaaa.authserver.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;


public class UserPrincipal implements UserDetails {

    private static String applicationName = "passport"; // Change it in SecurityConfig

    private final User user;

    private List<GrantedAuthority> authorities = new ArrayList<>();

    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;

    // For authentication and authorization in this application
    public UserPrincipal(User user) {
        this.user = user;

        JsonNode userConf = user.getConfig();
        if (userConf != null) {
            userConf.fieldNames().forEachRemaining(s -> authorities.add(new SimpleGrantedAuthority(s)));
            if (userConf.has(applicationName)) {
                JsonNode authNode = userConf.get(applicationName);
                if (authNode.has(UserAttributes.ROLES)) {
                    authNode.get(UserAttributes.ROLES).forEach(role -> this.authorities.add(new SimpleGrantedAuthority(role.asText())));
                }
                if (authNode.has(UserAttributes.CREDENTIALS_EXP)) {
                    if (Instant.ofEpochMilli(authNode.get(UserAttributes.CREDENTIALS_EXP).asLong()).isBefore(Instant.now())) {
                        this.credentialsNonExpired = false;
                    }
                }
            } else {
                this.accountNonLocked = false;
            }

            //check for date access for temporary user
            if (userConf.has(UserAttributes.TEMPORARY)) {
                LocalDate dateFrom = LocalDate.parse(userConf.get(UserAttributes.TEMPORARY).get("dateFrom").asText());
                LocalDate dateTo = LocalDate.parse(userConf.get(UserAttributes.TEMPORARY).get("dateTo").asText());
                if (dateFrom.isAfter(LocalDate.now()) || dateTo.isBefore(LocalDate.now())) {
                    this.accountNonExpired = false;
                }
            }
        } else {
            this.accountNonLocked = false;
        }
    }

    // For authentication and authorization in other applications
    public UserPrincipal(User user, String app) {
        this(user);

        JsonNode userConf = user.getConfig();
        if (userConf != null) {
            JsonNode appConfig = userConf.get(app);
            if (appConfig != null) {
                this.authorities.removeIf(grantedAuthority -> !app.equals(grantedAuthority.getAuthority()));
                if (appConfig.has(UserAttributes.ROLES)) {
                    appConfig.get(UserAttributes.ROLES).forEach(role -> this.authorities.add(new SimpleGrantedAuthority(role.asText())));
                }
                if (appConfig.has(UserAttributes.PRIVILEGES)) {
                    appConfig.get(UserAttributes.PRIVILEGES).forEach(privilege -> this.authorities.add(new SimpleGrantedAuthority(privilege.asText())));
                }
                ((ObjectNode) appConfig).remove(List.of(UserAttributes.ROLES, UserAttributes.PRIVILEGES));
                user.setConfig(appConfig);
            } else throw new IllegalArgumentException(String.format("There is no application [%s] for user [%s]", app, this.user.getLogin()));
        } else throw new IllegalArgumentException(String.format("There is no config for user [%s]", this.user.getLogin()));
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

    public User getUser() {
        return user;
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
        if (!(o instanceof UserPrincipal)) return false;
        UserPrincipal that = (UserPrincipal) o;
        return user.equals(that.user);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user);
    }
}
