package ru.loolzaaa.authserver.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserConfigWrapper implements Serializable {

    @JsonIgnore
    @Serial
    private static final long serialVersionUID = 3884005980531194740L;

    private JsonNode config;
}
