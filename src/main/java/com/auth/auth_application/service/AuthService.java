package com.auth.auth_application.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.auth_application.model.User;
import com.auth.auth_application.repository.UserRepository;

import java.util.Optional;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SessionManager sessionManager;

    public User register(User user) {
        logger.info("Attempting to register user: {}", user.getUsername());
        
        if (userRepository.existsByUsername(user.getUsername())) {
            logger.error("Registration failed: Username {} already exists", user.getUsername());
            throw new RuntimeException("Username already exists");
        }

        // Set default role if not specified
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }

        // Encrypt password before storing
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User registeredUser = userRepository.save(user);
        
        logger.info("User registered successfully: {}", registeredUser.getUsername());
        return registeredUser;
    }

    public Optional<User> authenticate(String username, String password) {
        logger.info("Attempting to authenticate user: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);
        
        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            logger.info("Authentication successful for user: {}", username);
            return userOpt;
        }

        logger.warn("Authentication failed for user: {}", username);
        return Optional.empty();
    }

    public void logout(String username) {
        logger.info("Logging out user: {}", username);
        sessionManager.invalidateSession(username);
        logger.info("User {} logged out successfully", username);
    }
}