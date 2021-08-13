package ru.loolzaaa.authserver.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;

@ControllerAdvice
public class ExceptionAdvice {
    @ExceptionHandler(RequestErrorException.class)
    ResponseEntity<RequestStatusDTO> requestError(RequestErrorException e) {
        RequestStatusDTO requestStatusDTO = RequestStatusDTO.badRequest(e.getMessage(), e.getObjects());
        return ResponseEntity.badRequest().body(requestStatusDTO);
    }
}
