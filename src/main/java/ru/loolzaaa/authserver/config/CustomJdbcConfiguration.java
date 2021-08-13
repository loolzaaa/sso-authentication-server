package ru.loolzaaa.authserver.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.jdbc.core.convert.JdbcCustomConversions;
import org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration;

import java.util.Arrays;

@RequiredArgsConstructor
@Configuration
public class CustomJdbcConfiguration extends AbstractJdbcConfiguration {

    private final ObjectMapper objectMapper;

    @Override
    public JdbcCustomConversions jdbcCustomConversions() {
        return new JdbcCustomConversions(Arrays.asList(new JsonNodeToStringConverter(), new StringToJsonNodeConverter()));
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
}
