// File: src/main/java/com/auth/exception/InvalidCredentialsException.java
package com.auth.auth_application.exception;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
}