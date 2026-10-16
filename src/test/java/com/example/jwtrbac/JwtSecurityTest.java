package com.example.jwtrbac;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class JwtSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private SecretKey getSigningKey() {
        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(jwtSecret);
            if (keyBytes.length < 32) {
                keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException e) {
            keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Test
    @DisplayName("Should return 401 Unauthorized for malformed JWT")
    void testAccessWithMalformedJwt() throws Exception {
        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer invalid.malformed.jwt.token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")));
    }

    @Test
    @DisplayName("Should return 401 Unauthorized for tampered JWT signature")
    void testAccessWithTamperedJwt() throws Exception {
        // Generate valid token then tamper with it
        String validToken = Jwts.builder()
                .subject("testuser")
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();

        // Tamper last character of signature
        String tamperedToken = validToken.substring(0, validToken.length() - 4) + "X9zQ";

        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + tamperedToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")));
    }

    @Test
    @DisplayName("Should return 401 Unauthorized for expired JWT")
    void testAccessWithExpiredJwt() throws Exception {
        // Token expired 10 minutes ago
        Date pastDate = new Date(System.currentTimeMillis() - 600000);
        Date evenMorePast = new Date(pastDate.getTime() - 600000);

        String expiredToken = Jwts.builder()
                .subject("testuser")
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(evenMorePast)
                .expiration(pastDate)
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();

        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")));
    }

    @Test
    @DisplayName("Should return 401 Unauthorized for JWT signed with untrusted secret key")
    void testAccessWithUntrustedKeyJwt() throws Exception {
        // Create an untrusted 256-bit key
        SecretKey untrustedKey = Keys.hmacShaKeyFor(
                "anothertotallydifferentsecretkeythatisatleast256bitslong!!".getBytes(StandardCharsets.UTF_8)
        );

        String untrustedToken = Jwts.builder()
                .subject("admin")
                .claim("roles", List.of("ROLE_ADMIN"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(untrustedKey, Jwts.SIG.HS256)
                .compact();

        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + untrustedToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)))
                .andExpect(jsonPath("$.error", is("Unauthorized")));
    }
}
