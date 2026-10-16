package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.response.UserProfileResponse;
import com.example.jwtrbac.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Authenticated user profile endpoint.
     * Accessible by users with ROLE_USER or ROLE_ADMIN.
     */
    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<UserProfileResponse> getUserProfile(Authentication authentication) {
        UserProfileResponse profile = authService.getCurrentUserProfile(authentication.getName());
        return ResponseEntity.ok(profile);
    }
}
