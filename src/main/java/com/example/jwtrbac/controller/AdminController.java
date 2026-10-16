package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.response.AdminDashboardResponse;
import com.example.jwtrbac.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AuthService authService;

    public AdminController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Administrative dashboard endpoint.
     * Strictly restricted to users with ROLE_ADMIN.
     */
    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminDashboardResponse> getAdminDashboard() {
        AdminDashboardResponse dashboard = authService.getAdminDashboard();
        return ResponseEntity.ok(dashboard);
    }
}
