# Spring Security JWT Demo

A complete Spring Security implementation with JWT (JSON Web Token) authentication for REST APIs.

## Overview

This project demonstrates:

- **JWT Authentication**: Stateless token-based authentication
- **Role-Based Access Control**: USER and ADMIN roles
- **Method-Level Security**: Using `@PreAuthorize` annotations
- **Password Encoding**: BCrypt for secure password storage
- **OpenAPI Documentation**: Swagger UI with security schemes

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ 1. POST /api/auth/login
       │    {email, password}
       ▼
┌─────────────────────────────────────────┐
│           Security Filter Chain          │
├─────────────────────────────────────────┤
│  JwtAuthenticationFilter                 │
│  - Extracts JWT from Authorization header│
│  - Validates token                       │
│  - Sets SecurityContext                  │
└──────┬──────────────────────────────────┘
       │
       │ 2. Returns JWT token
       │
       ▼
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ 3. GET /api/users/me
       │    Authorization: Bearer <token>
       ▼
┌─────────────────────────────────────────┐
│          Protected Resource              │
│  - Token validated by JwtAuthFilter     │
│  - User loaded from database            │
│  - Authorization checked                │
└─────────────────────────────────────────┘
```

## Project Structure

```
src/main/java/com/example/security/
├── SecurityJwtDemoApplication.java     # Main application
├── config/
│   ├── SecurityConfig.java             # Security configuration
│   ├── OpenApiConfig.java              # Swagger configuration
│   ├── GlobalExceptionHandler.java     # Error handling
│   └── DataInitializer.java            # Default users
├── controller/
│   ├── AuthController.java             # Login, register, refresh, logout
│   ├── UserController.java             # User operations
│   ├── AdminController.java            # Admin operations
│   └── PublicController.java           # Public endpoints
├── dto/
│   ├── AuthRequest.java                # Login request
│   ├── RegisterRequest.java            # Registration request
│   ├── AuthResponse.java               # Auth response with token
│   ├── MessageResponse.java            # Generic message response
│   ├── UserResponse.java               # User data response
│   └── ErrorResponse.java              # Error response
├── filter/
│   └── JwtAuthenticationFilter.java    # JWT validation filter
├── model/
│   ├── User.java                       # User entity
│   └── Role.java                       # Role enum
├── repository/
│   └── UserRepository.java             # User data access
└── service/
    ├── JwtService.java                 # JWT operations
    ├── AuthService.java                # Authentication logic
    ├── TokenBlacklistService.java      # Token revocation list
    └── UserService.java                # User operations
```

## Running the Application

```bash
# Navigate to project directory
cd spring-security-jwt-demo

# Run with Maven
mvn spring-boot:run

# Or build and run JAR
mvn clean package
java -jar target/spring-security-jwt-demo-1.0.0.jar
```

**Application starts at:** http://localhost:8080

**H2 Console:** http://localhost:8080/h2-console

Data is persisted locally in `./data/securitydb` (H2 file-based database).

## Default Users

The application creates default users on startup:

| Email | Password | Role |
|-------|----------|------|
| admin@example.com | Admin123! | ADMIN |
| user@example.com | User1234 | USER |

## API Endpoints

### Public Endpoints (No Auth Required)

```bash
# Health check
GET /api/public/health

# API info
GET /api/public/info
```

### Authentication Endpoints

```bash
# Register new user
POST /api/auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "Password123"
}

# Login
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "Password123"
}

# Refresh token
POST /api/auth/refresh
Authorization: Bearer <current_token>

# Logout (invalidate current token)
POST /api/auth/logout
Authorization: Bearer <token>
```

### User Endpoints (Auth Required)

```bash
# Get current user profile
GET /api/users/me
Authorization: Bearer <token>

# Get user by ID (own profile or ADMIN)
GET /api/users/{id}
Authorization: Bearer <token>

# Get all users (ADMIN only)
GET /api/users
Authorization: Bearer <token>

# Delete user (ADMIN only)
DELETE /api/users/{id}
Authorization: Bearer <token>
```

### Admin Endpoints (ADMIN Role Required)

```bash
# Promote user to admin
PATCH /api/admin/users/{id}/promote
Authorization: Bearer <token>

# Admin dashboard
GET /api/admin/dashboard
Authorization: Bearer <token>
```

## Testing the API

### Using cURL

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"Test1234"}'

# 2. Login to get token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test1234"}'

# Response:
# {
#   "token": "eyJhbGciOiJIUzI1...",
#   "type": "Bearer",
#   "expiresIn": 86400000,
#   "user": {...}
# }

# 3. Access protected endpoint
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1..."

# 4. Try admin endpoint (should fail with USER role)
curl http://localhost:8080/api/admin/dashboard \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1..."

# 5. Login as admin
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Admin123!"}'

# 6. Access admin endpoint (should work)
curl http://localhost:8080/api/admin/dashboard \
  -H "Authorization: Bearer <admin_token>"
```

### Using Swagger UI

1. Open http://localhost:8080/swagger-ui.html
2. Click "Authorize" button
3. Enter your JWT token (without "Bearer " prefix)
4. Try the endpoints

## Key Concepts

### Security Configuration

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())  // Disable for REST API
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**").permitAll()      // Public
            .requestMatchers("/api/admin/**").hasRole("ADMIN") // Admin only
            .anyRequest().authenticated()                      // Others need auth
        )
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
}
```

### JWT Token Flow

1. User logs in with email/password
2. Server validates credentials
3. Server generates JWT with user info and expiration
4. Server returns JWT to client
5. Client stores JWT (localStorage, cookie, etc.)
6. Client sends JWT in `Authorization: Bearer <token>` header
7. Server validates JWT on each request
8. Server extracts user info from JWT
9. Server authorizes based on user roles

### Method-Level Security

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping
public List<UserResponse> getAllUsers() { ... }

@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
@GetMapping("/{id}")
public UserResponse getUserById(@PathVariable Long id) { ... }
```

## Configuration

```yaml
# application.yml

jwt:
  secret: <base64-encoded-secret-key>  # At least 256 bits
  expiration: 86400000                  # 24 hours in milliseconds

spring:
  datasource:
    url: jdbc:h2:file:./data/securitydb
```

## Security Best Practices Demonstrated

1. **Password Encoding**: BCrypt with automatic salting
2. **Stateless Sessions**: No server-side session storage
3. **Token Expiration**: Configurable expiration time
4. **Role-Based Access**: Endpoint and method-level authorization
5. **Input Validation**: Bean Validation on DTOs
6. **Error Handling**: Consistent error responses
7. **Token Revocation on Logout**: In-memory blacklist for demo purposes
8. **CORS Configuration**: Controlled cross-origin access

## Dependencies

- Spring Boot 3.2.0
- Spring Security
- JJWT (io.jsonwebtoken) 0.12.3
- H2 Database
- SpringDoc OpenAPI 2.3.0
