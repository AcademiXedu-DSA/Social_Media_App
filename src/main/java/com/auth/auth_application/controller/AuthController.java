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
        //UserDetails holds the user's login information and roles, 
        //allowing Spring Security to ensure the user is who they say they are and can only access what they’re allowed to.
        UserDetails userDetails = org.springframework.security.core.userdetails.User
            .withUsername(registeredUser.getUsername())
            .password("")
            .authorities(registeredUser.getRole())
            .build();

        String token = jwtUtil.generateToken(userDetails);
        sessionManager.createSession(registeredUser.getUsername(),token);

        Map<String, String> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("token", token);
            response.put("username", registeredUser.getUsername());
            response.put("role", registeredUser.getRole());

        return ResponseEntity.ok(response);
    } catch (Exception e) {
        e.printStackTrace(); 
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
            response.put("role", user.getRole());

            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(401).body("Invalid username or password");
        }
 

        @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or missing token"));
        }

        try {
            String jwt = token.substring(7);
            String username = jwtUtil.extractUsername(jwt);
            
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(username)
                .password("")
                .authorities("USER")
                .build();

            if (!jwtUtil.validateToken(jwt, userDetails)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
            }

            authService.logout(username);
            return ResponseEntity.ok().body(Map.of("message", "Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Logout failed: " + e.getMessage()));
        }
    }
}

