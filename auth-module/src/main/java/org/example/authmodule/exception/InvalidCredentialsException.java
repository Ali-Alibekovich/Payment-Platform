package org.example.authmodule.exception;

import lombok.Getter;

@Getter
public class InvalidCredentialsException extends RuntimeException {

    private final Integer remainingAttempts;

    public InvalidCredentialsException() {
        this.remainingAttempts = null;
    }

    public InvalidCredentialsException(Integer remainingAttempts) {
        this.remainingAttempts = remainingAttempts;
    }

}
