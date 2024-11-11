package com.example.auth.service;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final SessionManager sessionManager;

    private UserDetails createUserDetails(String username, String role) {
        return org.springframework.security.core.userdetails.User
                .withUsername(username)
                .password("") // No password required for UserDetails in JWT
                .authorities(role)
                .build();
    }

    private Map<String, Object> buildAuthResponse(String token, String username, String role) {
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("username", username);
        response.put("role", role);
        return response;
    }

    public ResponseEntity<?> login(User user) {
        if (user.getUsername() == null || user.getPassword() == null) {
            return ResponseEntity.badRequest().body("Username and password are required!");
        }

        Optional<User> userOptional = userRepository.findByUsername(user.getUsername());
        if (userOptional.isEmpty() || !passwordEncoder.matches(user.getPassword(), userOptional.get().getPassword())) {
            return ResponseEntity.status(401).body("Invalid username or password!");
        }

        User existingUser = userOptional.get();
        UserDetails userDetails = createUserDetails(existingUser.getUsername(), existingUser.getRole());
        String token = jwtUtil.generateToken(userDetails);
        sessionManager.createSession(existingUser.getUsername(), token);

        return ResponseEntity.ok(buildAuthResponse(token, existingUser.getUsername(), existingUser.getRole()));
    }

    @Transactional
    public ResponseEntity<?> register(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.status(409).body("User already exists!");
        }

        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User createdUser = userRepository.save(user);

        UserDetails userDetails = createUserDetails(createdUser.getUsername(), createdUser.getRole());
        String token = jwtUtil.generateToken(userDetails);
        sessionManager.createSession(createdUser.getUsername(), token);

        Map<String, Object> response = new HashMap<>(Map.of("message", "User registered successfully"));
        response.putAll(buildAuthResponse(token, createdUser.getUsername(), createdUser.getRole()));

        return ResponseEntity.ok(response);
    }

    public ResponseEntity<Map<String, String>> logout(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or missing token"));
        }

        try {
            String jwt = token.substring(7);
            String username = jwtUtil.extractUsername(jwt);
            UserDetails userDetails = createUserDetails(username, "USER");

            if (!jwtUtil.validateToken(jwt, userDetails)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
            }

            sessionManager.invalidateSession(username);
            return ResponseEntity.ok().body(Map.of("message", "Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Logout failed: " + e.getMessage()));
        }
    }
}
