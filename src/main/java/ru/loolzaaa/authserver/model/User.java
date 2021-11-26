package ru.loolzaaa.authserver.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
@Table("users")
public class User {
    @Id
    private Long id;
    private String login;
    @JsonIgnore
    private String salt;
    private JsonNode config;
    private String name;
    private boolean enabled;
    @JsonIgnore
    @Transient
    private List<String> hashes = new LinkedList<>();

    @Builder
    public User(String login, String salt, JsonNode config, String name, boolean enabled) {
        this.login = login;
        this.salt = salt;
        this.config = config;
        this.name = name;
        this.enabled = enabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        User user = (User) o;
        return login.equals(user.login);
    }

    @Override
    public int hashCode() {
        return Objects.hash(login);
    }
}
