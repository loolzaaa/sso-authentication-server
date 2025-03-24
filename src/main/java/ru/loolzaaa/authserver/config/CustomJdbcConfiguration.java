package ru.loolzaaa.authserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.postgresql.util.PGobject;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration;
import ru.loolzaaa.authserver.model.UserConfigWrapper;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

@Log4j2
@Configuration
@RequiredArgsConstructor
public class CustomJdbcConfiguration extends AbstractJdbcConfiguration {

    private final ObjectMapper objectMapper;

    @Override
    protected List<?> userConverters() {
        return Arrays.asList(
                new UserConfigWrapperToJsonConverter(),
                new JsonToUserConfigWrapperConverter()
        );
    }

    @ReadingConverter
    class JsonToUserConfigWrapperConverter implements Converter<PGobject, UserConfigWrapper> {
        @Override
        public UserConfigWrapper convert(PGobject json) {
            try {
                JsonNode jsonNode = objectMapper.readTree(json.getValue());
                return new UserConfigWrapper(jsonNode);
            } catch (JsonProcessingException | NullPointerException e) {
                log.error(e);
            }
            return null;
        }
    }

    @WritingConverter
    class UserConfigWrapperToJsonConverter implements Converter<UserConfigWrapper, PGobject> {
        @Override
        public PGobject convert(UserConfigWrapper configWrapper) {
            PGobject json = new PGobject();
            json.setType("jsonb");
            try {
                json.setValue(objectMapper.writeValueAsString(configWrapper.getConfig()));
            } catch (SQLException | JsonProcessingException e) {
                log.error(e);
            }
            return json;
        }
    }
}
