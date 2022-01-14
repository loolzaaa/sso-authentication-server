package ru.loolzaaa.authserver.dto;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

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
