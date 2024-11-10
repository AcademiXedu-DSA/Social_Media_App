// File: src/main/java/com/auth/auth_application/service/SessionManager.java
package com.auth.auth_application.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class SessionManager {

    private static final Logger logger = LoggerFactory.getLogger(SessionManager.class);
    private final ConcurrentMap<String, String> userSessions = new ConcurrentHashMap<>();

    public void createSession(String username, String token) {
        userSessions.put(username, token);
        logger.info("Session created for user: {} with token: {}", username, token);
    }

    public void invalidateSession(String username) {
        userSessions.remove(username);
        logger.info("Session invalidated for user: {}", username);
    }

    public boolean isSessionValid(String username, String token) {
        String storedToken = userSessions.get(username);
        boolean isValid = storedToken != null && storedToken.equals(token);
        logger.debug("Session validation for user: {} with token: {}: {}", username, token, isValid ? "Valid" : "Invalid");
        return isValid;
    }
}
