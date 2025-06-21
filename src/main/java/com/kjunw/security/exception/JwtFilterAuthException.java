package com.kjunw.security.exception;

public class JwtFilterAuthException extends RuntimeException {

    public JwtFilterAuthException(String message) {
        super(message);
    }
}
