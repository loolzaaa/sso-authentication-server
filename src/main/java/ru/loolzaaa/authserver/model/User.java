package ru.loolzaaa.authserver.model;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;

import java.io.Serial;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
@Table("users")
public class User implements Serializable {

    @JsonIgnore
    @Serial
    private static final long serialVersionUID = 4932484828673582967L;

    @Id
    private Long id;
    private String login;
    @JsonIgnore
    private String salt;
    private UserConfigWrapper config;
    private String name;
    private boolean enabled;
    @JsonIgnore
    @Transient
    private List<String> hashes = new LinkedList<>();

    @Builder
    public User(String login, String salt, UserConfigWrapper config, String name, boolean enabled) {
        this.login = login;
        this.salt = salt;
        this.config = config;
        this.name = name;
        this.enabled = enabled;
    }

    @JsonGetter("config")
    public JsonNode getJsonConfig() {
        return config.getConfig();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(login, user.login);
    }

    @Override
    public int hashCode() {
        return Objects.hash(login);
    }
}
