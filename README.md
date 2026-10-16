# Spring Boot JWT Authentication & Role-Based Access Control (RBAC)

A secure, production-grade implementation of Role-Based Access Control (RBAC) and JSON Web Token (JWT) authentication built with Spring Boot 3.3, Spring Security 6, Spring Data JPA, and Java 17.

---

## 1. Architecture & Security Design

### Technology Stack
- **Java**: 17 LTS
- **Framework**: Spring Boot 3.3.4
- **Security**: Spring Security 6.3 (`@EnableMethodSecurity`, `SecurityFilterChain`)
- **Data & Persistence**: Spring Data JPA & Hibernate
- **Database**: H2 In-Memory Database (`jdbc:h2:mem:jwtrbacdb`)
- **Token Handling**: JJWT 0.12.6 (`io.jsonwebtoken`) with HMAC-SHA256
- **Password Hashing**: BCrypt (`BCryptPasswordEncoder`)
- **Validation**: Jakarta Bean Validation (`spring-boot-starter-validation`)
- **Testing**: JUnit 5, Spring Boot Test, Spring Security Test, MockMvc

---

## 2. Key Security Decisions

1. **Stateless Architecture**:
   - `SessionCreationPolicy.STATELESS` ensures Spring Security never creates or relies on server-side HTTP sessions.
2. **CSRF Configuration Rationale**:
   - CSRF protection is disabled (`AbstractHttpConfigurer::disable`) because this API is strictly stateless and relies on `Authorization: Bearer <token>` headers provided explicitly by the client rather than browser-managed ambient session cookies. Browsers do not automatically attach custom `Authorization` headers in cross-origin requests, eliminating CSRF vulnerabilities.
3. **Explicit 401 vs 403 Distinction**:
   - **401 Unauthorized** (`AuthEntryPointJwt`): Returned when an unauthenticated or invalid/expired token attempts access to a protected resource.
   - **403 Forbidden** (`CustomAccessDeniedHandler`): Returned when an authenticated user lacks the required role/authority (e.g., standard `ROLE_USER` attempting to access an administrative endpoint).
4. **Privilege Escalation Prevention**:
   - Public registration (`POST /api/auth/register`) strictly assigns `ROLE_USER`. Any attempt by the client to self-assign administrative roles (e.g., `ROLE_ADMIN` or `ADMIN`) is detected and rejected with `400 Bad Request`.
5. **No Stack Trace or Credential Leakage**:
   - Passwords and token secrets are never returned in API payloads (`@JsonIgnore` and dedicated DTO representations).
   - Global exception handling intercepts exceptions to prevent leaking server internal details or stack traces to callers.
6. **Configurable Secrets via Environment Variables**:
   - Secrets are loaded dynamically with external fallback via `${JWT_SECRET}` and `${JWT_EXPIRATION_MS}`.

---

## 3. Pre-Seeded Default Accounts

For development and immediate testing, the database is pre-seeded on startup with:

| Username | Password | Email | Assigned Roles |
|---|---|---|---|
| `admin` | `Admin@12345` | `admin@example.com` | `ROLE_ADMIN`, `ROLE_USER` |
| `testuser` | `User@12345` | `testuser@example.com` | `ROLE_USER` |

*(All passwords in the database are hashed using BCrypt.)*

---

## 4. API Endpoints Reference

| Method | Endpoint | Required Role | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | Public | Register a new user account (defaults to `ROLE_USER`) |
| `POST` | `/api/auth/login` | Public | Authenticate credentials and receive Bearer JWT |
| `GET` | `/api/user/profile` | `ROLE_USER` or `ROLE_ADMIN` | Retrieve currently authenticated user's profile |
| `GET` | `/api/admin/dashboard` | `ROLE_ADMIN` | Administrative metrics and system status |

---

## 5. Quickstart & Testing with cURL

### 1. Register a New User
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "developer",
    "email": "dev@example.com",
    "password": "Password@123"
  }'
```
**Response (201 Created):**
```json
{
  "message": "User registered successfully"
}
```

---

### 2. Login (User)
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "developer",
    "password": "Password@123"
  }'
```
**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "id": 3,
  "username": "developer",
  "email": "dev@example.com",
  "roles": [
    "ROLE_USER"
  ]
}
```

---

### 3. Access User Profile (Authenticated)
```bash
curl -X GET http://localhost:8080/api/user/profile \
  -H "Authorization: Bearer <TOKEN>"
```
**Response (200 OK):**
```json
{
  "id": 3,
  "username": "developer",
  "email": "dev@example.com",
  "roles": [
    "ROLE_USER"
  ],
  "createdAt": "2026-10-16T13:20:00.000"
}
```

---

### 4. Attempt Accessing Admin Dashboard as Normal User (Forbidden)
```bash
curl -X GET http://localhost:8080/api/admin/dashboard \
  -H "Authorization: Bearer <USER_TOKEN>"
```
**Response (403 Forbidden):**
```json
{
  "timestamp": "2026-10-16T07:50:21.485Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Access denied: insufficient permissions to access this resource",
  "path": "/api/admin/dashboard"
}
```

---

### 5. Login as Administrator & Access Dashboard
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin@12345"
  }'
```
Then call:
```bash
curl -X GET http://localhost:8080/api/admin/dashboard \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
**Response (200 OK):**
```json
{
  "message": "Admin dashboard access granted",
  "totalUsers": 2,
  "serverTime": "2026-10-16T13:20:25.123",
  "systemStatus": "OPERATIONAL"
}
```

---

## 6. How to Run the Application & Tests

### Build & Run Tests
```powershell
.\mvnw.cmd clean test
```

### Run the Application
```powershell
.\mvnw.cmd spring-boot:run
```

---

## 7. Environment Configuration

Copy `.env.example` to `.env` or set environment variables before running in production:

```bash
JWT_SECRET=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
JWT_EXPIRATION_MS=86400000
PORT=8080
```
