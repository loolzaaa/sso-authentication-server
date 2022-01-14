package ru.loolzaaa.authserver.repositories;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.loolzaaa.authserver.model.User;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findByLogin(String username);

    @Modifying
    @Query("UPDATE users SET config = :config::jsonb WHERE login = :login")
    void updateConfigByLogin(@Param("config") JsonNode config, @Param("login") String login);

    @Modifying
    @Query("UPDATE users SET salt = :salt WHERE login = :login")
    void updateSaltByLogin(@Param("salt") String salt, @Param("login") String login);
}
