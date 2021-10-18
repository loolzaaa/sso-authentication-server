package ru.loolzaaa.authserver.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import ru.loolzaaa.authserver.services.UserControlService;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.*;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    UserControlService userControlService;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = standaloneSetup(new UserController(userControlService))
                .alwaysExpect(content().contentType(MediaType.APPLICATION_JSON))
                .build();
    }

    @Test
    @Disabled
    void shouldReturnNullIfUserNotExist() throws Exception {
        //INCORRECT TEST ! ! !
        when(userControlService.getUserByUsername(anyString(), any())).thenReturn(null);

        mockMvc.perform(get("/api/fast/user/get/{username}", "user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").doesNotExist());
    }
}