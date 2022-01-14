package ru.loolzaaa.authserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.postgresql.util.PGobject;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class CustomJdbcConfiguration extends AbstractJdbcConfiguration {

    private final ObjectMapper objectMapper;

    @Override
    protected List<?> userConverters() {
        return Arrays.asList(
                new JsonNodeToJsonConverter(),
                new JsonToJsonNodeConverter(),
                new StringToJsonNodeConverter(),
                new JsonNodeToStringConverter()
        );
    }

    @ReadingConverter
    class JsonToJsonNodeConverter implements Converter<PGobject, JsonNode> {
        @Override
        public JsonNode convert(PGobject json) {
            try {
                return objectMapper.readTree(json.getValue());
            } catch (JsonProcessingException | NullPointerException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    @WritingConverter
    class JsonNodeToJsonConverter implements Converter<JsonNode, PGobject> {
        @Override
        public PGobject convert(JsonNode jsonNode) {
            PGobject json = new PGobject();
            json.setType("jsonb");
            try {
                json.setValue(objectMapper.writeValueAsString(jsonNode));
            } catch (SQLException | JsonProcessingException e) {
                e.printStackTrace();
            }
            return json;
        }
    }

    @ReadingConverter
    class StringToJsonNodeConverter implements Converter<String, JsonNode> {
        @Override
        public JsonNode convert(String s) {
            try {
                return objectMapper.readTree(s);
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    @WritingConverter
    class JsonNodeToStringConverter implements Converter<JsonNode, String> {
        @Override
        public String convert(JsonNode jsonNode) {
            try {
                return objectMapper.writeValueAsString(jsonNode);
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            return null;
        }
    }
}
