package com.auth.auth_application.controller;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import com.auth.auth_application.config.JwtUtil;
import com.auth.auth_application.entity.User;
import com.auth.auth_application.service.AuthService;
import com.auth.auth_application.service.SessionManager;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private SessionManager sessionManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
    try {
        User registeredUser = authService.register(user);
        UserDetails userDetails = org.springframework.security.core.userdetails.User
            .withUsername(registeredUser.getUsername())
            .password("")
            .authorities(registeredUser.getRole())
            .build();

        String token = jwtUtil.generateToken(userDetails);
        sessionManager.createSession(registeredUser.getUsername(), token);

        Map<String, String> response = new HashMap<>();
        response.put("username", registeredUser.getUsername());
        response.put("token", token);

        return ResponseEntity.ok(response);
    } catch (Exception e) {
        // Log the error
        e.printStackTrace(); // For debugging purposes
        return ResponseEntity.badRequest().body("Error during registration: " + e.getMessage());
    }
}

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        Optional<User> userOpt = authService.authenticate(user.getUsername(), user.getPassword());
        if (userOpt.isPresent()) {
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(userOpt.get().getUsername())
                .password("")
                .authorities(userOpt.get().getRole())
                .build();

            String token = jwtUtil.generateToken(userDetails);
            sessionManager.createSession(userOpt.get().getUsername(), token);

            Map<String, String> response = new HashMap<>();
            response.put("username", userOpt.get().getUsername());
            response.put("token", token);

            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(401).body("Invalid username or password");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        sessionManager.invalidateSession(username);
        return ResponseEntity.ok("User logged out successfully");
    }
}
