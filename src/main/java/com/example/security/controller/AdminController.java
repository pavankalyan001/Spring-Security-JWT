package com.example.security.controller;

import com.example.security.dto.UserResponse;
import com.example.security.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Admin Controller.
 *
 * All endpoints require ADMIN role.
 * Configured via URL pattern in SecurityConfig: /api/admin/** -> ADMIN role
 */
@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin", description = "Administrative operations (ADMIN role required)")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "Promote user to admin", description = "Change a user's role to ADMIN")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User promoted to admin"),
        @ApiResponse(responseCode = "403", description = "Access denied - ADMIN role required"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PatchMapping("/users/{id}/promote")
    public ResponseEntity<UserResponse> promoteToAdmin(@PathVariable Long id) {
        logger.info("Promoting user {} to ADMIN", id);
        return userService.promoteToAdmin(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "Get admin dashboard", description = "Get admin dashboard information")
    @GetMapping("/dashboard")
    public ResponseEntity<String> getDashboard() {
        logger.debug("Accessing admin dashboard");
        return ResponseEntity.ok("Welcome to Admin Dashboard!");
    }
}
