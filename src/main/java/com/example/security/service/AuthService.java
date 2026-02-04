package com.example.security.service;

import com.example.security.dto.*;
import com.example.security.model.Role;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
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
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
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
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid token format");
        }

        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);

        User user = userRepository.findByEmail(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!jwtService.isTokenValid(token, user)) {
            throw new IllegalArgumentException("Invalid or expired token");
        }

        logger.info("Token refreshed for user: {}", user.getEmail());

        String newToken = jwtService.generateToken(user);

        return new AuthResponse(
            newToken,
            jwtService.getExpirationTime(),
            UserResponse.fromEntity(user)
        );
    }
}
