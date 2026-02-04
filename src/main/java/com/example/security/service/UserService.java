package com.example.security.service;

import com.example.security.dto.UserResponse;
import com.example.security.model.Role;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service for user operations.
 *
 * Also implements UserDetailsService for Spring Security integration.
 */
@Service
@Transactional
public class UserService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Load user by username (email) for Spring Security.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found with email: " + username));
    }

    /**
     * Get all users.
     */
    public List<UserResponse> getAllUsers() {
        logger.debug("Fetching all users");
        return userRepository.findAll().stream()
                .map(UserResponse::fromEntity)
                .collect(Collectors.toList());
    }

    /**
     * Get user by ID.
     */
    public Optional<UserResponse> getUserById(Long id) {
        logger.debug("Fetching user with id: {}", id);
        return userRepository.findById(id)
                .map(UserResponse::fromEntity);
    }

    /**
     * Get user by email.
     */
    public Optional<UserResponse> getUserByEmail(String email) {
        logger.debug("Fetching user with email: {}", email);
        return userRepository.findByEmail(email)
                .map(UserResponse::fromEntity);
    }

    /**
     * Promote user to admin role.
     */
    public Optional<UserResponse> promoteToAdmin(Long id) {
        logger.info("Promoting user {} to ADMIN", id);
        return userRepository.findById(id)
                .map(user -> {
                    user.setRole(Role.ADMIN);
                    User saved = userRepository.save(user);
                    logger.info("User {} promoted to ADMIN", saved.getEmail());
                    return UserResponse.fromEntity(saved);
                });
    }

    /**
     * Delete user by ID.
     */
    public boolean deleteUser(Long id) {
        logger.info("Deleting user with id: {}", id);
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            logger.info("User {} deleted", id);
            return true;
        }
        return false;
    }
}
