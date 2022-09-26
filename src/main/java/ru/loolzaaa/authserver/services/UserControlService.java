package ru.loolzaaa.authserver.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.loolzaaa.authserver.config.security.bean.CustomPBKDF2PasswordEncoder;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
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

@Log4j2
@RequiredArgsConstructor
@Service
public class UserControlService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final SsoServerProperties ssoServerProperties;

    private final JdbcTemplate jdbcTemplate;

    private final UserRepository userRepository;

    private final AuthenticationProvider authenticationProvider;

    private final CustomPBKDF2PasswordEncoder passwordEncoder;

    public UserPrincipal getUserByUsername(String username, String appName) {
        User user = userRepository.findByLogin(username).orElse(null);
        if (user == null) {
            log.debug("Try to receive invalid user [{}] for app [{}]", username, appName);
            throw new RequestErrorException("There is no user with login [%s]", username);
        }
        try {
            log.trace("Return user principal [{}] for application [{}]", username, appName);
            return new UserPrincipal(user, appName);
        } catch (Exception e) {
            log.warn("Can't create user principal: {}", username, e);
            throw new RequestErrorException(e.getMessage());
        }
    }

    public List<UserPrincipal> getUsersByAuthority(String appName, String authority) {
        Iterable<User> allUsers = userRepository.findAll();
        SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authority);
        List<UserPrincipal> users = new ArrayList<>();
        try {
            for (User u : allUsers) {
                UserPrincipal userPrincipal;
                try {
                    userPrincipal = new UserPrincipal(u, appName);
                    if (userPrincipal.getAuthorities().contains(grantedAuthority)) {
                        users.add(userPrincipal);
                    }
                } catch (IllegalArgumentException ignored) {
                    log.debug("Can't create user by authority [{}] in application [{}]", authority, appName);
                }
            }
            log.debug("Return {} users by authority [{}] in application [{}]", users.size(), authority, appName);
            return users;
        } catch (Exception e) {
            log.warn("Can't return users by authority [{}] in application [{}]: ", authority, appName, e);
            throw new RequestErrorException(e.getMessage());
        }
    }

    @Transactional
    public RequestStatusDTO createUser(String app, CreateUserRequestDTO newUser) {
        String login = newUser.getLogin();

        User user = userRepository.findByLogin(login).orElse(null);

        if (user != null) {
            if (user.getConfig().has(app)) {
                log.warn("Try to add [{}] application in user [{}] where it already exist", app, login);
                throw new RequestErrorException("App [%s] for user [%s] already exist!", app, login);
            } else {
                ((ObjectNode) user.getConfig()).set(app, newUser.getConfig());
                userRepository.updateConfigByLogin(user.getConfig(), login);

                log.info("Added [{}] application for user [{}]", app, login);
                return RequestStatusDTO.ok("Add new app [%s] for user [%s]", app, login);
            }
        }

        log.info("Try to create new user: {}. Start application: {}", login, app);
        String tempPassword = generateTempPassword();
        String salt = passwordEncoder.generateSalt();
        passwordEncoder.setSalt(salt);
        String hash = passwordEncoder.encode(tempPassword);
        passwordEncoder.setSalt(null);

        String name = newUser.getName();
        if (name == null || name.length() < 3 || name.length() > 128) {
            log.warn("Invalid name for new user: {}", login);
            throw new RequestErrorException("Name property [%s] for user [%s] must not be null and 3-128 length", name, login);
        }

        ObjectNode config = objectMapper.createObjectNode();
        config.putObject(ssoServerProperties.getApplication().getName())
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(365)).toEpochMilli());
        if (!config.has(app)) config.set(app, newUser.getConfig());

        user = User.builder().login(login).salt(salt).config(config).name(name).enabled(true).build();
        userRepository.save(user);

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", hash);

        log.info("Create new user [{}] with start application: {}", login, app);
        return RequestStatusDTO.ok("User [%s] created. Temp pass: %s", login, tempPassword);
    }

    @Transactional
    public RequestStatusDTO deleteUser(String login, String password) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to delete non existing user: {}", login);
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        boolean isHashDeleted;
        try {
            isHashDeleted = checkUserAndDeleteHash(user, password);
        } catch (BadCredentialsException e) {
            log.warn("Incorrect password for user [{}] to delete", login);
            throw new RequestErrorException("Incorrect password for user [%s]", user.getLogin());
        } catch (Exception e) {
            log.error("Some error while user [{}] delete process", login, e);
            throw new RequestErrorException("Some error while user [%s] delete process: %s", user.getLogin(), e.getMessage());
        }

        jdbcTemplate.update("DELETE FROM refresh_sessions WHERE user_id = ?", user.getId());
        userRepository.delete(user);

        log.info("Delete user [{}]. Hash {} database", login, isHashDeleted ? "deleted from" : "stayed in");
        return RequestStatusDTO.ok("User [%s] deleted. Hash %s database", login, isHashDeleted ? "deleted from" : "stayed in");
    }

    @Transactional
    public RequestStatusDTO changeUserPassword(String login, String oldPassword, String newPassword) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to change password for non existing user: {}", login);
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        try {
            checkUserAndDeleteHash(user, oldPassword);
        } catch (BadCredentialsException e) {
            log.warn("Incorrect password for user [{}] to change password", login);
            throw new RequestErrorException("Incorrect password for user [%s]", user.getLogin());
        } catch (Exception e) {
            log.error("Some error while user [{}] change password process", login, e);
            throw new RequestErrorException("Some error while user [%s] change password process: %s", user.getLogin(), e.getMessage());
        }

        String salt = passwordEncoder.generateSalt();
        passwordEncoder.setSalt(salt);
        String newHash = passwordEncoder.encode(newPassword);
        passwordEncoder.setSalt(null);

        userRepository.updateSaltByLogin(salt, login);

        ((ObjectNode) user.getConfig().get(ssoServerProperties.getApplication().getName()))
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(365)).toEpochMilli());

        if (user.getConfig().has(UserAttributes.TEMPORARY)) {
            ((ObjectNode) user.getConfig().get(UserAttributes.TEMPORARY)).put("pass", newPassword);
            userRepository.updateConfigByLogin(user.getConfig(), login);
        }

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", newHash);

        log.info("Password for user [{}] changed", login);
        return RequestStatusDTO.ok("Password for user [%s] changed", login);
    }

    @Transactional
    public RequestStatusDTO resetUserPassword(String login, String newPassword) {
        String password = newPassword;
        if (newPassword == null) {
            password = generateTempPassword();
        }
        changeUserPassword(login, null, password);
        log.info("Password for user [{}] reset", login);
        return RequestStatusDTO.ok("Password for user [%s] reset. New password: %s",
                login, newPassword == null ? password : "[]");
    }

    @Transactional
    public RequestStatusDTO changeApplicationConfigForUser(String login, String app, JsonNode appConfig) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to change config for non existing user: {}", login);
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        JsonNode userConfig = user.getConfig();
        if (!userConfig.has(app)) {
            log.warn("Try to change non existing config [{}] for user: {}", app, login);
            throw new RequestErrorException("There is no [%s] config for user [%s]", app, login);
        }

        ((ObjectNode) user.getConfig()).set(app, appConfig);
        userRepository.updateConfigByLogin(user.getConfig(), login);

        log.info("Application [{}] config was changed for user [{}]", app, login);
        return RequestStatusDTO.ok("User [%s] configuration for [%s] changed", login, app);
    }

    @Transactional
    public RequestStatusDTO deleteApplicationConfigForUser(String login, String app) {
        if (ssoServerProperties.getApplication().getName().equals(app)) {
            log.error("Try to delete {} config for user: {}", ssoServerProperties.getApplication().getName(), login);
            throw new RequestErrorException("Cannot delete %s configuration", ssoServerProperties.getApplication().getName());
        }

        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to delete config for non existing user: {}", login);
            throw new RequestErrorException("There is no user with login [%s]", login);
        }

        JsonNode userConfig = user.getConfig();
        if (!userConfig.has(app)) {
            log.warn("Try to delete non existing config [{}] for user: {}", app, login);
            throw new RequestErrorException("There is no [%s] config for user [%s]", app, login);
        }

        ((ObjectNode) user.getConfig()).remove(app);
        userRepository.updateConfigByLogin(user.getConfig(), login);

        log.info("Application [{}] config was deleted for user [{}]", app, login);
        return RequestStatusDTO.ok("User [%s] configuration for [%s] removed", login, app);
    }

    @Transactional
    public RequestStatusDTO createTemporaryUser(String temporaryLogin, long dateFrom, long dateTo) {
        String dTemporaryLogin = "d_" + temporaryLogin;
        String dTemporaryPassword = generatePasswordForTemporaryUser();

        User temporaryUser = userRepository.findByLogin(temporaryLogin).orElse(null);
        User dTemporaryUser = userRepository.findByLogin(dTemporaryLogin).orElse(null);

        if (temporaryUser == null) {
            log.warn("Try to create temporary user for non existing user: {}", temporaryLogin);
            throw new RequestErrorException("There is no original user [%s]", temporaryLogin);
        }
        if (temporaryUser.getConfig().has(UserAttributes.TEMPORARY)) {
            log.warn("Try to create temporary user for ALREADY temporary user: {}", temporaryLogin);
            throw new RequestErrorException("Temporary users can't create other temporary users");
        }
        if (dTemporaryUser != null) {
            log.warn("Try to create already exists temporary user: {}", dTemporaryLogin);
            throw new RequestErrorException("Temporary user [%s] already exist", dTemporaryLogin);
        }

        LocalDateTime dateFromLdt = new Timestamp(dateFrom).toLocalDateTime();
        LocalDateTime dateToLdt = new Timestamp(dateTo).toLocalDateTime();
        LocalDateTime now = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);

        if (dateFromLdt.isBefore(now) || dateFromLdt.isAfter(dateToLdt) ||
                dateFromLdt.isEqual(dateToLdt) || dateToLdt.isEqual(now) ||
                dateToLdt.isBefore(now)) {
            log.debug("Try to create temporary user [{}] with wrong dates", dTemporaryLogin);
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

        ((ObjectNode) temporaryUser.getConfig().get(ssoServerProperties.getApplication().getName()))
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

        log.info("Temporary user [{}] created for user [{}]", dTemporaryLogin, temporaryLogin);
        return RequestStatusDTO.ok("Temporary user [%s] created. Temporary password: %s", dTemporaryLogin, dTemporaryPassword);
    }

    @Transactional
    private boolean checkUserAndDeleteHash(User user, String password) {
        boolean isHashDeleted = false;
        if (password != null) {
            try {
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(user.getLogin(), password));
            } catch (AccountStatusException ex) {
                if (!user.getConfig().has(UserAttributes.TEMPORARY)) {
                    throw ex;
                }
            }
            passwordEncoder.setSalt(user.getSalt());
            String hash = passwordEncoder.encode(password);
            passwordEncoder.setSalt(null);
            if (jdbcTemplate.update("DELETE FROM hashes WHERE hash = ?", hash) > 0) {
                isHashDeleted = true;
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
