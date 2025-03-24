package ru.loolzaaa.authserver.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateUserRequestDTO {
    @NotNull
    @Size(min = 3, max = 32)
    private String login;
    private String name;
    @NotNull
    private JsonNode config;
}
