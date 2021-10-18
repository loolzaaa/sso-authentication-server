package ru.loolzaaa.authserver.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.loolzaaa.authserver.config.security.bean.CustomPBKDF2PasswordEncoder;
import ru.loolzaaa.authserver.dto.CreateUserRequestDTO;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserAttributes;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class UserControlService {

    @Value("${auth.application.name}")
    private String applicationName;

    private static ObjectMapper objectMapper = new ObjectMapper();

    private final JdbcTemplate jdbcTemplate;

    private final UserRepository userRepository;

    private final AuthenticationProvider authenticationProvider;

    private final CustomPBKDF2PasswordEncoder passwordEncoder;

    public UserPrincipal getUserByUsername(String username, String appName) {
        User user = userRepository.findByLogin(username).orElse(null);
        if (user == null) {
            throw new RequestErrorException("There is no user with login [%s]", username);
        }
        try {
            return new UserPrincipal(user, appName);
        } catch (Exception e) {
            throw new RequestErrorException(e.getMessage());
        }
    }

    public List<UserPrincipal> getUsersByRole(String role, String appName) {
        Iterable<User> allUsers = userRepository.findAll();
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);
        List<UserPrincipal> users = new ArrayList<>();
        try {
            for (User u : allUsers) {
                UserPrincipal userPrincipal = new UserPrincipal(u, appName);
                if (userPrincipal.getAuthorities().contains(authority)) {
                    users.add(userPrincipal);
                }
            }
            return users;
        } catch (Exception e) {
            throw new RequestErrorException(e.getMessage());
        }
    }

    @Transactional
    public RequestStatusDTO createUser(String app, CreateUserRequestDTO newUser) {
        String login = newUser.getLogin();

        User user = userRepository.findByLogin(login).orElse(null);

        if (user != null) {
            if (user.getConfig().has(app)) {
                throw new RequestErrorException("App [%s] for user [%s] already exist!", app, login);
            } else {
                ((ObjectNode) user.getConfig()).set(app, newUser.getConfig());
                userRepository.updateConfigByLogin(user.getConfig(), login);

                return RequestStatusDTO.ok("Add new app [%s] for user [%s]", app, login);
            }
        }

        String tempPassword = generateTempPassword();
        String salt = passwordEncoder.generateSalt();
        passwordEncoder.setSalt(salt);
        String hash = passwordEncoder.encode(tempPassword);
        passwordEncoder.setSalt(null);

        String name = newUser.getName();

        ObjectNode config = objectMapper.createObjectNode();
        config.putObject(applicationName)
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(365)).toEpochMilli());
        if (!config.has(app)) config.set(app, newUser.getConfig());

        user = User.builder().login(login).salt(salt).config(config).name(name).enabled(true).build();
        userRepository.save(user);

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", hash);

        return RequestStatusDTO.ok("User [%s] created. Temp pass: %s", login, tempPassword);
    }

    @Transactional
    public RequestStatusDTO deleteUser(String login, String password) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        boolean isHashDeleted = checkUserAndDeleteHash(user, password);

        jdbcTemplate.update("DELETE FROM refresh_sessions WHERE user_id = ?", user.getId());
        userRepository.delete(user);

        return RequestStatusDTO.ok("User [%s] deleted. Hash %s database", login, isHashDeleted ? "deleted from" : "stayed in");
    }

    @Transactional
    public RequestStatusDTO changeUserPassword(String login, String oldPassword, String newPassword) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        checkUserAndDeleteHash(user, oldPassword);

        String salt = passwordEncoder.generateSalt();
        passwordEncoder.setSalt(salt);
        String newHash = passwordEncoder.encode(newPassword);
        passwordEncoder.setSalt(null);

        userRepository.updateSaltByLogin(salt, login);

        ((ObjectNode) user.getConfig().get(applicationName))
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(365)).toEpochMilli());

        if (user.getConfig().has(UserAttributes.TEMPORARY)) {
            ((ObjectNode) user.getConfig().get(UserAttributes.TEMPORARY)).put("pass", newPassword);
            userRepository.updateConfigByLogin(user.getConfig(), login);
        }

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", newHash);

        return RequestStatusDTO.ok("Password for user [%s] changed", login);
    }

    @Transactional
    public RequestStatusDTO resetUserPassword(String login, String newPassword) {
        String password = newPassword;
        if (newPassword == null) {
            password = generateTempPassword();
        }
        changeUserPassword(login, null, password);
        return RequestStatusDTO.ok("Password for user [%s] reset. New password: %s",
                login, newPassword == null ? password : "[]");
    }

    @Transactional
    public RequestStatusDTO changeApplicationConfigForUser(String login, String app, JsonNode appConfig) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        JsonNode userConfig = user.getConfig();
        if (!userConfig.has(app)) {
            throw new RequestErrorException("There is no [%s] config for user [%s]", app, login);
        }

        ((ObjectNode) user.getConfig()).set(app, appConfig);
        userRepository.updateConfigByLogin(user.getConfig(), login);

        return RequestStatusDTO.ok("User [%s] configuration for [%s] changed", login, app);
    }

    @Transactional
    public RequestStatusDTO deleteApplicationConfigForUser(String login, String app) {
        if (applicationName.equals(app)) {
            throw new RequestErrorException("Cannot delete %s configuration", applicationName);
        }

        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        JsonNode userConfig = user.getConfig();
        if (!userConfig.has(app)) {
            throw new RequestErrorException("There is no [%s] config for user [%s]", app, login);
        }

        ((ObjectNode) user.getConfig()).remove(app);
        userRepository.updateConfigByLogin(user.getConfig(), login);

        return RequestStatusDTO.ok("User [%s] configuration for [%s] removed", login, app);
    }

    @Transactional
    public RequestStatusDTO createTemporaryUser(String temporaryLogin, long dateFrom, long dateTo) {
        String dTemporaryLogin = "d_" + temporaryLogin;
        String dTemporaryPassword = generatePasswordForTemporaryUser();

        User temporaryUser = userRepository.findByLogin(temporaryLogin).orElse(null);
        User dTemporaryUser = userRepository.findByLogin(dTemporaryLogin).orElse(null);

        if (temporaryUser == null) {
            throw new RequestErrorException("There is no original user [%s]", temporaryLogin);
        }
        if (temporaryUser.getConfig().has(UserAttributes.TEMPORARY)) {
            throw new RequestErrorException("Temporary users can't create other temporary users");
        }
        if (dTemporaryUser != null) {
            throw new RequestErrorException("Temporary user [%s] already exist", dTemporaryLogin);
        }

        LocalDateTime dateFromLdt = new Timestamp(dateFrom).toLocalDateTime();
        LocalDateTime dateToLdt = new Timestamp(dateTo).toLocalDateTime();
        LocalDateTime now = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);

        if (dateFromLdt.isBefore(now) || dateFromLdt.isAfter(dateToLdt) ||
                dateFromLdt.isEqual(dateToLdt) || dateToLdt.isEqual(now) ||
                dateToLdt.isBefore(now)) {
            throw new RequestErrorException("Wrong dates for temporary user");
        }

        String salt = passwordEncoder.generateSalt();
        passwordEncoder.setSalt(salt);
        String hash = passwordEncoder.encode(dTemporaryPassword);
        passwordEncoder.setSalt(null);

        ObjectNode temporaryNode = objectMapper.createObjectNode();
        temporaryNode.put("dateFrom", dateFromLdt.toLocalDate().toString());
        temporaryNode.put("dateTo", dateToLdt.toLocalDate().toString());
        temporaryNode.put("pass", dTemporaryPassword);
        temporaryNode.put("originTabNumber", temporaryLogin);
        ((ObjectNode) temporaryUser.getConfig()).set(UserAttributes.TEMPORARY, temporaryNode);

        ((ObjectNode) temporaryUser.getConfig().get(applicationName))
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(90)).toEpochMilli());

        dTemporaryUser = User.builder()
                .login(dTemporaryLogin)
                .salt(salt)
                .config(temporaryUser.getConfig())
                .name(String.format("%s (%s)", temporaryLogin, temporaryUser.getName()))
                .enabled(true)
                .build();
        userRepository.save(dTemporaryUser);

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", hash);

        //TODO: Some notifications?

        return RequestStatusDTO.ok("Temporary user [%s] created. Temporary password: %s", dTemporaryLogin, dTemporaryPassword);
    }

    @Transactional
    private boolean checkUserAndDeleteHash(User user, String password) {
        boolean isHashDeleted = false;
        if (password != null) {
            try {
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(user.getLogin(), password));
                passwordEncoder.setSalt(user.getSalt());
                String hash = passwordEncoder.encode(password);
                passwordEncoder.setSalt(null);
                if (jdbcTemplate.update("DELETE FROM hashes WHERE hash = ?", hash) > 0) {
                    isHashDeleted = true;
                }
            } catch (BadCredentialsException e) {
                throw new RequestErrorException("Incorrect password for user [%s]", user.getLogin());
            }
        }
        return isHashDeleted;
    }

    private String generateTempPassword() {
        return "temp" + (int)(Math.random() * 1000);
    }

    private String generatePasswordForTemporaryUser() {
        Random r = new Random();
        return r.ints(8, 97, 123)
                .mapToObj(value -> String.valueOf((char) value)).collect(Collectors.joining());
    }
}
