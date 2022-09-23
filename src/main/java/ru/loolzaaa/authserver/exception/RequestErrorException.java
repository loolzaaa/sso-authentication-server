package ru.loolzaaa.authserver.exception;

import lombok.Getter;

@Getter
public class RequestErrorException extends RuntimeException {

    private final Object[] objects;

    public RequestErrorException(String message, Object... objects) {
        super(message);
        this.objects = objects;
    }
}
