package ru.loolzaaa.authserver.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.test.web.servlet.MockMvc;
import ru.loolzaaa.authserver.services.UserControlService;

@WebMvcTest(value = UserController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class,
        excludeFilters = @ComponentScan.Filter(type = FilterType.REGEX, pattern = ".+.security.*"))
class UserControllerTestIT {

    @Autowired
    private MockMvc mvc;

    @MockBean
    UserControlService userControlService;

    @BeforeEach
    void setUp() {
    }

    @Test
    void someTest() {

    }
}