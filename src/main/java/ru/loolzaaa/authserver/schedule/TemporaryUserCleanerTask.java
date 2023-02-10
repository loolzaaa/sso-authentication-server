package ru.loolzaaa.authserver.schedule;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserAttributes;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;
import ru.loolzaaa.authserver.services.UserControlService;

import java.util.Locale;
import java.util.concurrent.Callable;

@Log4j2
@RequiredArgsConstructor
@Component
@Profile("prod")
public class TemporaryUserCleanerTask implements Callable<Integer> {

    private final SsoServerProperties ssoServerProperties;

    private final UserRepository userRepository;

    private final UserControlService userControlService;

    @Scheduled(cron = "0 0 0 * * *")
    @Override
    public Integer call() {
        String appName = ssoServerProperties.getApplication().getName();
        int deleteUserCounter = 0;
        Iterable<User> users = userRepository.findAll();
        for (User u : users) {
            String pass = null;
            if (u.getJsonConfig().get(appName).has(UserAttributes.TEMPORARY)) {
                pass = u.getJsonConfig().get(appName).get(UserAttributes.TEMPORARY).get("pass").asText();
            }
            UserPrincipal userPrincipal = new UserPrincipal(u);
            if (!userPrincipal.isAccountNonExpired()) {
                try {
                    RequestStatusDTO result = userControlService.deleteUser(u.getLogin(), pass, Locale.US);
                    deleteUserCounter++;
                    log.info(result.getText());
                } catch (RequestErrorException e) {
                    log.error(e.getMessage());
                } catch (Exception e) {
                    log.error(e);
                }
            }
        }
        return deleteUserCounter;
    }
}
