package com.example.jwtsecurity.service;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Manages user sessions, storing JWT tokens associated with usernames.  This is a simple in-memory implementation and should be replaced with a persistent solution for production.
 */
@Component
public class SessionManager {
    private final Map<String, String> userSessions = new HashMap<>();

    /**
     * Creates a new session, associating a username with a JWT token.
     * @param username The username.
     * @param token The JWT token.
     */
    public void createSession(String username, String token) {
        userSessions.put(username, token);
    }

    /**
     * Invalidates a user's session by removing their token.
     * @param username The username.
     */
    public void invalidateSession(String username) {
        userSessions.remove(username);
    }

    /**
     * Checks if a user's session is valid by comparing the stored token with the provided token.
     * @param username The username.
     * @param token The JWT token.
     * @return True if the session is valid, false otherwise.
     */
    public boolean isSessionValid(String username, String token) {
        String storedToken = userSessions.get(username);
        return storedToken != null && storedToken.equals(token);
    }
}
