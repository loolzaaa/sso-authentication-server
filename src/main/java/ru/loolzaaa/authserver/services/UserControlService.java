package ru.loolzaaa.authserver.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.MessageSource;
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
import ru.loolzaaa.authserver.model.UserConfigWrapper;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;
import ru.loolzaaa.authserver.webhook.WebhookEvent;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.stream.Collectors;

@Log4j2
@RequiredArgsConstructor
@Service
public class UserControlService {

    private final Random random = new Random();

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final SsoServerProperties ssoServerProperties;

    private final MessageSource messageSource;

    private final WebhookService webhookService;

    private final JdbcTemplate jdbcTemplate;

    private final UserRepository userRepository;

    private final AuthenticationProvider authenticationProvider;

    private final CustomPBKDF2PasswordEncoder passwordEncoder;

    public UserPrincipal getUserByUsername(String username, String appName, Locale l) {
        User user = userRepository.findByLogin(username).orElse(null);
        if (user == null) {
            log.debug("Try to receive invalid user [{}] for app [{}]", username, appName);
            String message = messageSource.getMessage("userControl.userNotFound", new Object[]{username}, l);
            throw new RequestErrorException(message);
        }
        try {
            log.trace("Return user principal [{}] for application [{}]", username, appName);
            return new UserPrincipal(user, appName);
        } catch (Exception e) {
            log.warn("Can't create user principal: {}", username, e);
            String message = messageSource.getMessage("userControl.common.error", new Object[]{e.getMessage()}, l);
            throw new RequestErrorException(message);
        }
    }

    public List<UserPrincipal> getUsersByAuthority(String appName, String authority, Locale l) {
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
            String message = messageSource.getMessage("userControl.common.error", new Object[]{e.getMessage()}, l);
            throw new RequestErrorException(message);
        }
    }

    @Transactional
    public RequestStatusDTO createUser(String app, CreateUserRequestDTO newUser, Locale l) {
        String login = newUser.getLogin();

        User user = userRepository.findByLogin(login).orElse(null);

        if (user != null) {
            if (user.getJsonConfig().has(app)) {
                log.warn("Try to add [{}] application in user [{}] where it already exist", app, login);
                String message = messageSource.getMessage("userControl.create.appExistError", new Object[]{app, login}, l);
                throw new RequestErrorException(message);
            } else {
                ((ObjectNode) user.getJsonConfig()).set(app, newUser.getConfig());
                userRepository.updateConfigByLogin(user.getConfig(), login);

                log.info("Added [{}] application for user [{}]", app, login);
                String message = messageSource.getMessage("userControl.create.appAddOk", new Object[]{app, login}, l);
                return RequestStatusDTO.ok(message);
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
            String message = messageSource.getMessage("userControl.create.invalidUsername", new Object[]{name, login}, l);
            throw new RequestErrorException(message);
        }

        ObjectNode config = objectMapper.createObjectNode();
        config.putObject(ssoServerProperties.getApplication().getName())
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(365)).toEpochMilli());
        if (!config.has(app)) config.set(app, newUser.getConfig());

        user = User.builder()
                .login(login)
                .salt(salt)
                .config(new UserConfigWrapper(config))
                .name(name)
                .enabled(true)
                .build();
        userRepository.save(user);

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", hash);

        log.info("Create new user [{}] with start application: {}", login, app);
        String message = messageSource.getMessage("userControl.create.success", new Object[]{login, tempPassword}, l);
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO deleteUser(String login, String password, Locale l) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to delete non existing user: {}", login);
            String message = messageSource.getMessage("userControl.userNotFound", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }

        boolean isHashDeleted;
        try {
            isHashDeleted = checkUserAndDeleteHash(user, password);
        } catch (BadCredentialsException e) {
            log.warn("Incorrect password for user [{}] to delete", login);
            String message = messageSource.getMessage("userControl.delete.incorrectPassword", new Object[]{user.getLogin()}, l);
            throw new RequestErrorException(message);
        } catch (Exception e) {
            log.error("Some error while user [{}] delete process", login, e);
            String message = messageSource.getMessage("userControl.delete.error", new Object[]{user.getLogin(), e.getMessage()}, l);
            throw new RequestErrorException(message);
        }

        jdbcTemplate.update("DELETE FROM refresh_sessions WHERE user_id = ?", user.getId());
        userRepository.delete(user);
        webhookService.fireEvent(WebhookEvent.DELETE_USER, login);

        String hashStatus = messageSource.getMessage("userControl.delete.hash" + (isHashDeleted ? "Del" : "Stay"), null, l);
        log.info("Delete user [{}]. Hash {} database", login, hashStatus);
        String message = messageSource.getMessage("userControl.delete.success", new Object[]{login, hashStatus}, l);
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO changeUserLockStatus(String login, Boolean enabled, Boolean lock, Locale l) {
        if (enabled == null && lock == null) {
            log.warn("Try to change NONE of enabled/lock flags for user: {}", login);
            String message = messageSource.getMessage("userControl.lock.none", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }
        if (enabled != null && lock != null) {
            log.warn("Try to change BOTH of enabled/lock flags for user: {}", login);
            String message = messageSource.getMessage("userControl.lock.both", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }

        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to lock non existing user: {}", login);
            String message = messageSource.getMessage("userControl.userNotFound", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }

        String message = null;
        if (enabled != null) {
            userRepository.updateEnabledByLogin(enabled, login);
            log.info("User [{}] {}", login, enabled ? "enabled" : "disabled");
            message = messageSource.getMessage("userControl.lock." + (enabled ? "enabled" : "disabled"), new Object[]{login}, l);
        }
        if (lock != null) {
            JsonNode userConfig = user.getJsonConfig();
            ((ObjectNode) userConfig.get(ssoServerProperties.getApplication().getName())).put(UserAttributes.LOCK, lock);
            userRepository.updateConfigByLogin(user.getConfig(), login);
            log.info("User [{}] {}", login, lock ? "locked" : "unlocked");
            message = messageSource.getMessage("userControl.lock." + (lock ? "locked" : "unlocked"), new Object[]{login}, l);
        }
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO changeUserPassword(String login, String oldPassword, String newPassword, Locale l) {
        String appName = ssoServerProperties.getApplication().getName();
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to change password for non existing user: {}", login);
            String message = messageSource.getMessage("userControl.userNotFound", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }

        try {
            checkUserAndDeleteHash(user, oldPassword);
        } catch (BadCredentialsException e) {
            log.warn("Incorrect password for user [{}] to change password", login);
            String message = messageSource.getMessage("userControl.changePassword.incorrectPassword", new Object[]{user.getLogin()}, l);
            throw new RequestErrorException(message);
        } catch (Exception e) {
            log.error("Some error while user [{}] change password process", login, e);
            String message = messageSource.getMessage("userControl.changePassword.error", new Object[]{user.getLogin(), e.getMessage()}, l);
            throw new RequestErrorException(message);
        }

        String salt = passwordEncoder.generateSalt();
        passwordEncoder.setSalt(salt);
        String newHash = passwordEncoder.encode(newPassword);
        passwordEncoder.setSalt(null);

        userRepository.updateSaltByLogin(salt, login);

        ((ObjectNode) user.getJsonConfig().get(appName))
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(Duration.ofDays(365)).toEpochMilli());

        if (user.getJsonConfig().get(appName).has(UserAttributes.TEMPORARY)) {
            ((ObjectNode) user.getJsonConfig().get(appName).get(UserAttributes.TEMPORARY))
                    .put("pass", newPassword);
            userRepository.updateConfigByLogin(user.getConfig(), login);
        }

        jdbcTemplate.update("INSERT INTO hashes VALUES (?)", newHash);

        log.info("Password for user [{}] changed", login);
        String message = messageSource.getMessage("userControl.changePassword.success", new Object[]{login}, l);
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO resetUserPassword(String login, String newPassword, Locale l) {
        String password = newPassword;
        if (newPassword == null) {
            password = generateTempPassword();
        }
        changeUserPassword(login, null, password, l);
        log.info("Password for user [{}] reset", login);
        String message = messageSource.getMessage("userControl.resetPassword.success",
                new Object[]{login, newPassword == null ? password : "[]"}, l);
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO changeApplicationConfigForUser(String login, String app, JsonNode appConfig, Locale l) {
        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to change config for non existing user: {}", login);
            String message = messageSource.getMessage("userControl.userNotFound", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }

        JsonNode userConfig = user.getJsonConfig();
        if (!userConfig.has(app)) {
            log.warn("Try to change non existing config [{}] for user: {}", app, login);
            String message = messageSource.getMessage("userControl.configNotFound", new Object[]{app, login}, l);
            throw new RequestErrorException(message);
        }

        ((ObjectNode) user.getJsonConfig()).set(app, appConfig);
        userRepository.updateConfigByLogin(user.getConfig(), login);

        log.info("Application [{}] config was changed for user [{}]", app, login);
        String message = messageSource.getMessage("userControl.changeConfig.success", new Object[]{login, app}, l);
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO deleteApplicationConfigForUser(String login, String app, Locale l) {
        if (ssoServerProperties.getApplication().getName().equals(app)) {
            log.error("Try to delete {} config for user: {}", ssoServerProperties.getApplication().getName(), login);
            String message = messageSource.getMessage("userControl.deleteConfig.error",
                    new Object[]{ssoServerProperties.getApplication().getName()}, l);
            throw new RequestErrorException(message);
        }

        User user = userRepository.findByLogin(login).orElse(null);

        if (user == null) {
            log.warn("Try to delete config for non existing user: {}", login);
            String message = messageSource.getMessage("userControl.userNotFound", new Object[]{login}, l);
            throw new RequestErrorException(message);
        }

        JsonNode userConfig = user.getJsonConfig();
        if (!userConfig.has(app)) {
            log.warn("Try to delete non existing config [{}] for user: {}", app, login);
            String message = messageSource.getMessage("userControl.configNotFound", new Object[]{app, login}, l);
            throw new RequestErrorException(message);
        }

        ((ObjectNode) user.getJsonConfig()).remove(app);
        userRepository.updateConfigByLogin(user.getConfig(), login);

        log.info("Application [{}] config was deleted for user [{}]", app, login);
        String message = messageSource.getMessage("userControl.deleteConfig.success", new Object[]{login, app}, l);
        return RequestStatusDTO.ok(message);
    }

    @Transactional
    public RequestStatusDTO createTemporaryUser(String temporaryLogin, long dateFrom, long dateTo, Locale l) {
        String appName = ssoServerProperties.getApplication().getName();
        String dTemporaryLogin = "d_" + temporaryLogin;
        String dTemporaryPassword = generatePasswordForTemporaryUser();

        User temporaryUser = userRepository.findByLogin(temporaryLogin).orElse(null);
        User dTemporaryUser = userRepository.findByLogin(dTemporaryLogin).orElse(null);

        if (temporaryUser == null) {
            log.warn("Try to create temporary user for non existing user: {}", temporaryLogin);
            String message = messageSource.getMessage("userControl.temporary.userNotFound", new Object[]{temporaryLogin}, l);
            throw new RequestErrorException(message);
        }
        if (temporaryUser.getJsonConfig().get(appName).has(UserAttributes.TEMPORARY)) {
            log.warn("Try to create temporary user for ALREADY temporary user: {}", temporaryLogin);
            String message = messageSource.getMessage("userControl.temporary.tempCreateTemp", null, l);
            throw new RequestErrorException(message);
        }
        if (dTemporaryUser != null) {
            log.warn("Try to create already exists temporary user: {}", dTemporaryLogin);
            String message = messageSource.getMessage("userControl.temporary.alreadyExist", new Object[]{dTemporaryLogin}, l);
            throw new RequestErrorException(message);
        }

        LocalDateTime dateFromLdt = new Timestamp(dateFrom).toLocalDateTime();
        LocalDateTime dateToLdt = new Timestamp(dateTo).toLocalDateTime();
        LocalDateTime now = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);
        Duration dateDiff = Duration.between(dateFromLdt, dateToLdt);

        if (dateFromLdt.isBefore(now) || dateFromLdt.isAfter(dateToLdt) ||
                dateFromLdt.isEqual(dateToLdt) || dateToLdt.isEqual(now) ||
                dateToLdt.isBefore(now)) {
            log.debug("Try to create temporary user [{}] with wrong dates", dTemporaryLogin);
            String message = messageSource.getMessage("userControl.temporary.datesError", null, l);
            throw new RequestErrorException(message);
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
        ((ObjectNode) temporaryUser.getJsonConfig().get(appName))
                .set(UserAttributes.TEMPORARY, temporaryNode);

        ((ObjectNode) temporaryUser.getJsonConfig().get(appName))
                .put(UserAttributes.CREDENTIALS_EXP, Instant.now().plus(dateDiff).toEpochMilli());

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
        String message = messageSource.getMessage("userControl.temporary.success",
                new Object[]{dTemporaryLogin, dTemporaryPassword}, l);
        return RequestStatusDTO.ok(message);
    }

    private boolean checkUserAndDeleteHash(User user, String password) {
        boolean isHashDeleted = false;
        if (password != null) {
            try {
                authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(user.getLogin(), password));
            } catch (AccountStatusException ex) {
                JsonNode userConfig = user.getJsonConfig().get(ssoServerProperties.getApplication().getName());
                if (!userConfig.has(UserAttributes.TEMPORARY)) {
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
        return "temp" + random.nextInt(1000);
    }

    private String generatePasswordForTemporaryUser() {
        return random.ints(8, 97, 123)
                .mapToObj(value -> String.valueOf((char) value)).collect(Collectors.joining());
    }
}
