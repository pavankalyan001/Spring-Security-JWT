package com.example.security.service;

import com.example.security.dto.AuthRequest;
import com.example.security.dto.AuthResponse;
import com.example.security.dto.RegisterRequest;
import com.example.security.dto.UserResponse;
import com.example.security.model.Role;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service for authentication operations.
 *
 * Handles:
 * - User registration (with password encoding)
 * - User authentication (login)
 * - Token refresh
 * - Logout (token revocation)
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       AuthenticationManager authenticationManager,
                       TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    /**
     * Register a new user.
     */
    public AuthResponse register(RegisterRequest request) {
        logger.info("Registering new user: {}", request.email());

        // Check if user already exists
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        // Create new user with encoded password
        User user = new User();
        user.setName(request.name());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(Role.USER);

        userRepository.save(user);
        logger.info("User registered successfully: {}", user.getEmail());

        // Generate token
        String token = jwtService.generateToken(user);

        return new AuthResponse(
                token,
                jwtService.getExpirationTime(),
                UserResponse.fromEntity(user)
        );
    }

    /**
     * Authenticate user and return token.
     */
    public AuthResponse authenticate(AuthRequest request) {
        logger.info("Authenticating user: {}", request.email());

        // Authenticate using Spring Security
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        // Get user
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        logger.info("User authenticated successfully: {}", user.getEmail());

        // Generate token
        String token = jwtService.generateToken(user);

        return new AuthResponse(
                token,
                jwtService.getExpirationTime(),
                UserResponse.fromEntity(user)
        );
    }

    /**
     * Refresh an existing token.
     */
    public AuthResponse refreshToken(String authHeader) {
        String token = extractToken(authHeader);
        User user = getUserFromToken(token);

        if (!jwtService.isTokenValid(token, user)) {
            throw new BadCredentialsException("Invalid or expired token");
        }

        logger.info("Token refreshed for user: {}", user.getEmail());

        String newToken = jwtService.generateToken(user);

        return new AuthResponse(
                newToken,
                jwtService.getExpirationTime(),
                UserResponse.fromEntity(user)
        );
    }

    /**
     * Logout by revoking the current token.
     */
    public void logout(String authHeader) {
        String token = extractToken(authHeader);
        User user = getUserFromToken(token);

        if (!jwtService.isTokenValid(token, user)) {
            throw new BadCredentialsException("Invalid or expired token");
        }

        tokenBlacklistService.revoke(token, jwtService.extractExpiration(token));
        logger.info("User logged out successfully: {}", user.getEmail());
    }

    private String extractToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new BadCredentialsException("Invalid token format");
        }
        return authHeader.substring(7);
    }

    private User getUserFromToken(String token) {
        try {
            String username = jwtService.extractUsername(token);
            return userRepository.findByEmail(username)
                    .orElseThrow(() -> new BadCredentialsException("User not found"));
        } catch (JwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid or expired token");
        }
    }
}
