package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.request.LoginRequest;
import com.example.jwtrbac.dto.request.RegisterRequest;
import com.example.jwtrbac.dto.response.JwtResponse;
import com.example.jwtrbac.dto.response.MessageResponse;
import com.example.jwtrbac.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Public user registration endpoint.
     * Enforces password hashing, validation, and prevents privilege escalation.
     */
    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        MessageResponse response = authService.registerUser(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Public user login endpoint.
     * Validates credentials and returns JWT bearer token upon success.
     */
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse response = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(response);
    }
}
