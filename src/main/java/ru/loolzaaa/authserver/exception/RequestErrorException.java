package ru.loolzaaa.authserver.exception;

public class RequestErrorException extends RuntimeException {

    private Object[] objects;

    public RequestErrorException(String message, Object... objects) {
        super(message);
        this.objects = objects;
    }

    public Object[] getObjects() {
        return objects;
    }
}
