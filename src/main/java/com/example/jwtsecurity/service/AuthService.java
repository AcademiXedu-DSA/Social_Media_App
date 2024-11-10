package com.example.jwtsecurity.service;

import com.example.jwtsecurity.model.User;
import com.example.jwtsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service class for authentication and user management.
 */
@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SessionManager sessionManager;

    /**
     * Registers a new user.  Encrypts the password before saving.  Sets a default role if none is provided.
     * @param user The user to register.
     * @return The registered user.
     * @throws RuntimeException if the username already exists.
     */
    public User register(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        // Set default role if not specified
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }

        // Encrypt password before storing
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * Authenticates a user based on username and password.
     * @param username The user's username.
     * @param password The user's password.
     * @return An Optional containing the user if authentication is successful, Optional.empty() otherwise.
     */
    public Optional<User> authenticate(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            return userOpt;
        }

        return Optional.empty();
    }

    /**
     * Logs out a user by invalidating their session.
     * @param username The username of the user to log out.
     */
    public void logout(String username) {
        sessionManager.invalidateSession(username);
    }
}
