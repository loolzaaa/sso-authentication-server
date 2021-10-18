package ru.loolzaaa.authserver.schedule;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserAttributes;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;
import ru.loolzaaa.authserver.services.UserControlService;

import java.util.concurrent.Callable;

import static java.lang.String.*;

@Log4j2
@RequiredArgsConstructor
@Component
@Profile("prod")
public class TemporaryUserCleanerTask implements Callable<Integer> {

    private final UserRepository userRepository;

    private final UserControlService userControlService;

    @Scheduled(initialDelay = 60 * 1000, fixedDelay = 24 * 60 * 60 * 1000)
    @Override
    public Integer call() {
        int deleteUserCounter = 0;
        Iterable<User> users = userRepository.findAll();
        for (User u : users) {
            UserPrincipal userPrincipal = new UserPrincipal(u);
            if (!userPrincipal.isAccountNonExpired()) {
                String pass = u.getConfig().get(UserAttributes.TEMPORARY).get("pass").asText();
                try {
                    RequestStatusDTO result = userControlService.deleteUser(u.getLogin(), pass);
                    deleteUserCounter++;
                    log.info(result.getText());
                } catch (RequestErrorException e) {
                    log.error(format(e.getMessage(), e.getObjects()));
                } catch (Exception e) {
                    log.error(e);
                }
            }
        }
        return deleteUserCounter;
    }
}
