package com.example.jwtrbac;

import com.example.jwtrbac.dto.request.LoginRequest;
import com.example.jwtrbac.dto.response.JwtResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class EndpointAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String userToken;
    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        // Authenticate standard user ('testuser' / 'User@12345')
        LoginRequest userLogin = new LoginRequest("testuser", "User@12345");
        MvcResult userResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userLogin)))
                .andExpect(status().isOk())
                .andReturn();
        JwtResponse userJwt = objectMapper.readValue(userResult.getResponse().getContentAsString(), JwtResponse.class);
        this.userToken = userJwt.getToken();

        // Authenticate administrator ('admin' / 'Admin@12345')
        LoginRequest adminLogin = new LoginRequest("admin", "Admin@12345");
        MvcResult adminResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminLogin)))
                .andExpect(status().isOk())
                .andReturn();
        JwtResponse adminJwt = objectMapper.readValue(adminResult.getResponse().getContentAsString(), JwtResponse.class);
        this.adminToken = adminJwt.getToken();
    }

    @Test
    @DisplayName("Should return 401 Unauthorized when accessing user profile without token")
    void testAccessUserProfileWithoutToken() throws Exception {
        mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")))
                .andExpect(jsonPath("$.message", containsString("Full authentication is required")));
    }

    @Test
    @DisplayName("Should return 401 Unauthorized when accessing admin dashboard without token")
    void testAccessAdminDashboardWithoutToken() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")));
    }

    @Test
    @DisplayName("Should return 200 OK when accessing user profile with valid user token")
    void testAccessUserProfileWithValidUserToken() throws Exception {
        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.email", is("testuser@example.com")))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_USER")))
                .andExpect(jsonPath("$.password").doesNotExist()); // Ensure password hash is NEVER exposed
    }

    @Test
    @DisplayName("Should return 403 Forbidden when normal user attempts to access admin dashboard")
    void testAccessAdminDashboardWithNormalUserToken() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status", is(403)))
                .andExpect(jsonPath("$.error", is("Forbidden")))
                .andExpect(jsonPath("$.message", containsString("insufficient permissions")));
    }

    @Test
    @DisplayName("Should return 200 OK when admin accesses admin dashboard")
    void testAccessAdminDashboardWithAdminToken() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", is("Admin dashboard access granted")))
                .andExpect(jsonPath("$.totalUsers", greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.systemStatus", is("OPERATIONAL")));
    }

    @Test
    @DisplayName("Should return 200 OK when admin accesses user profile")
    void testAccessUserProfileWithAdminToken() throws Exception {
        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is("admin")))
                .andExpect(jsonPath("$.roles", hasItems("ROLE_ADMIN", "ROLE_USER")));
    }
}
