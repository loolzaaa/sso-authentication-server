package ru.loolzaaa.authserver.repositories;

import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserConfigWrapper;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findByLogin(String username);

    @Modifying
    @Query("UPDATE users SET enabled = :enabled WHERE login = :login")
    void updateEnabledByLogin(@Param("enabled") boolean enabled, @Param("login") String login);

    @Modifying
    @Query("UPDATE users SET config = :config::jsonb WHERE login = :login")
    void updateConfigByLogin(@Param("config") UserConfigWrapper config, @Param("login") String login);

    @Modifying
    @Query("UPDATE users SET salt = :salt WHERE login = :login")
    void updateSaltByLogin(@Param("salt") String salt, @Param("login") String login);
}
