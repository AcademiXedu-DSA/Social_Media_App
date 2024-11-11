package com.example.auth.service;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class SessionManager {
    private final ConcurrentMap<String, String> userSessions = new ConcurrentHashMap<>();

    public void createSession(String username, String token) {
        userSessions.put(username, token);
    }

    public void invalidateSession(String username) {
        userSessions.remove(username);
    }

    public boolean isSessionValid(String username, String token) {
        String storedToken = userSessions.get(username);
        return storedToken != null && storedToken.equals(token);
    }
}
