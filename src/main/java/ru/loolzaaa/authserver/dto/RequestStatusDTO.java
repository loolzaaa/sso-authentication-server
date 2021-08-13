package ru.loolzaaa.authserver.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import static java.lang.String.format;

@Getter
@Setter
@Builder
public class RequestStatusDTO {
    private RequestStatus status;
    private HttpStatus statusCode;
    private String text;

    public static RequestStatusDTO ok(String text, Object... objects) {
        return RequestStatusDTO.builder()
                .status(RequestStatus.OK)
                .statusCode(HttpStatus.OK)
                .text(format(text, objects))
                .build();
    }

    public static RequestStatusDTO badRequest(String text, Object... objects) {
        return RequestStatusDTO.builder()
                .status(RequestStatus.ERROR)
                .statusCode(HttpStatus.BAD_REQUEST)
                .text(format(text, objects))
                .build();
    }
}
