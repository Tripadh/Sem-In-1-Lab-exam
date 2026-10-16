package com.example.jwtrbac;

import com.example.jwtrbac.dto.request.LoginRequest;
import com.example.jwtrbac.dto.request.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Should successfully register a new user")
    void testRegisterSuccess() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "newuser",
                "newuser@example.com",
                "Password@123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message", containsString("User registered successfully")));
    }

    @Test
    @DisplayName("Should reject registration with duplicate username")
    void testRegisterDuplicateUsername() throws Exception {
        // 'testuser' is seeded on startup by DataInitializer
        RegisterRequest request = new RegisterRequest(
                "testuser",
                "distinct_email@example.com",
                "Password@123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status", is(409)))
                .andExpect(jsonPath("$.error", is("Conflict")))
                .andExpect(jsonPath("$.message", containsString("already taken")));
    }

    @Test
    @DisplayName("Should reject registration with duplicate email")
    void testRegisterDuplicateEmail() throws Exception {
        // 'testuser@example.com' is seeded on startup by DataInitializer
        RegisterRequest request = new RegisterRequest(
                "uniqueusername123",
                "testuser@example.com",
                "Password@123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status", is(409)))
                .andExpect(jsonPath("$.error", is("Conflict")))
                .andExpect(jsonPath("$.message", containsString("already in use")));
    }

    @Test
    @DisplayName("Should reject registration with invalid payload (Bean Validation)")
    void testRegisterInvalidPayload() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "", // Blank username
                "not-an-email", // Invalid email
                "123" // Password too short (<6)
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.validationErrors.username", notNullValue()))
                .andExpect(jsonPath("$.validationErrors.email", notNullValue()))
                .andExpect(jsonPath("$.validationErrors.password", notNullValue()));
    }

    @Test
    @DisplayName("Should strictly prevent users from self-assigning ADMIN role")
    void testSelfAssignAdminRoleRejected() throws Exception {
        RegisterRequest request = new RegisterRequest(
                "hacker_user",
                "hacker@example.com",
                "Password@123",
                Set.of("ROLE_ADMIN")
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.message", containsString("Self-assignment of administrative roles is strictly prohibited")));
    }

    @Test
    @DisplayName("Should successfully authenticate with valid credentials")
    void testLoginSuccess() throws Exception {
        // 'testuser' / 'User@12345' is seeded on startup
        LoginRequest request = new LoginRequest("testuser", "User@12345");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.type", is("Bearer")))
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_USER")));
    }

    @Test
    @DisplayName("Should fail authentication with invalid password")
    void testLoginInvalidPassword() throws Exception {
        LoginRequest request = new LoginRequest("testuser", "WrongPassword!99");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")))
                .andExpect(jsonPath("$.message", containsString("Invalid username/email or password")));
    }

    @Test
    @DisplayName("Should fail authentication with non-existent user")
    void testLoginUserNotFound() throws Exception {
        LoginRequest request = new LoginRequest("nonexistent_user", "AnyPassword123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")))
                .andExpect(jsonPath("$.message", containsString("Invalid username/email or password")));
    }
}
