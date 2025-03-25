package ru.loolzaaa.authserver.schedule;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import ru.loolzaaa.authserver.config.security.property.SsoServerProperties;
import ru.loolzaaa.authserver.dto.RequestStatus;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserAttributes;
import ru.loolzaaa.authserver.model.UserConfigWrapper;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;
import ru.loolzaaa.authserver.services.UserControlService;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class TemporaryUserCleanerTaskTest {

    final String app = "passport";

    @Mock
    UserRepository userRepository;

    @Mock
    UserControlService userControlService;

    TemporaryUserCleanerTask temporaryUserCleanerTask;

    @BeforeEach
    void setUp() {
        SsoServerProperties properties = new SsoServerProperties();
        properties.getApplication().setName(app);

        temporaryUserCleanerTask = new TemporaryUserCleanerTask(properties, userRepository, userControlService);

        UserPrincipal.setApplicationName(app);
    }

    @Test
    void test() {
        final RequestStatusDTO result = RequestStatusDTO.builder()
                .status(RequestStatus.OK)
                .statusCode(HttpStatus.OK)
                .text("TEXT")
                .build();
        given(userRepository.findAll()).willReturn(getFakeUsers());
        given(userControlService.deleteUser(anyString(), anyString(), any())).willReturn(result);

        Integer call = temporaryUserCleanerTask.call();

        assertThat(call).isEqualTo(2);
    }

    Iterable<User> getFakeUsers() {
        LocalDate now = LocalDate.now();
        ObjectMapper mapper = new ObjectMapper();

        List<User> users = new ArrayList<>();

        User user1 = new User();
        user1.setLogin("L1");
        ObjectNode config1 = mapper.createObjectNode();
        ObjectNode appNode1 = mapper.createObjectNode();
        config1.set(app, appNode1);
        ObjectNode temporaryNode1 = mapper.createObjectNode();
        temporaryNode1.put("dateFrom", now.plusDays(1).toString());
        temporaryNode1.put("dateTo", now.plusDays(1).toString());
        temporaryNode1.put("pass", "PASS");
        appNode1.set(UserAttributes.TEMPORARY, temporaryNode1);
        user1.setConfig(new UserConfigWrapper(config1));
        users.add(user1);

        User user2 = new User();
        user2.setLogin("L2");
        ObjectNode config2 = mapper.createObjectNode();
        ObjectNode appNode2 = mapper.createObjectNode();
        config2.set(app, appNode2);
        ObjectNode temporaryNode2 = mapper.createObjectNode();
        temporaryNode2.put("dateFrom", now.minusDays(1).toString());
        temporaryNode2.put("dateTo", now.minusDays(1).toString());
        temporaryNode2.put("pass", "PASS");
        appNode2.set(UserAttributes.TEMPORARY, temporaryNode2);
        user2.setConfig(new UserConfigWrapper(config2));
        users.add(user2);

        User user3 = new User();
        user3.setLogin("L3");
        ObjectNode config3 = mapper.createObjectNode();
        ObjectNode appNode3 = mapper.createObjectNode();
        config3.set(app, appNode3);
        user3.setConfig(new UserConfigWrapper(config3));
        users.add(user3);

        return users;
    }
}