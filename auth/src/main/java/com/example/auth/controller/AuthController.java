package com.example.auth.controller;

import com.example.auth.service.AuthService;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");
        authService.register(username, password);
        return ResponseEntity.ok("User registered successfully");
    }
    

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");
        String token = authService.login(username, password);
        
        if (token != null) {
            return ResponseEntity.ok(token);
        }
        
        return ResponseEntity.status(401).body("Invalid credentials");
    }
}
