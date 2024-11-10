// File: src/main/java/com/auth/exception/UserAlreadyExistsException.java
package com.auth.auth_application.exception;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}