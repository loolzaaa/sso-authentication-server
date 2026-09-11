package ru.loolzaaa.authserver.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;

@Slf4j
@ControllerAdvice
public class ExceptionAdvice {

    @ExceptionHandler(RequestErrorException.class)
    ResponseEntity<RequestStatusDTO> requestError(RequestErrorException e) {
        log.debug("Request error: {}", e.getMessage());
        RequestStatusDTO requestStatusDTO = RequestStatusDTO.badRequest(e.getMessage());
        return ResponseEntity.badRequest().body(requestStatusDTO);
    }
}
