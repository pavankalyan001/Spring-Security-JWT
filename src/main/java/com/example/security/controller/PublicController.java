package com.example.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Public Controller.
 *
 * Endpoints that don't require authentication.
 * Useful for health checks, status, and public information.
 */
@RestController
@RequestMapping("/api/public")
@Tag(name = "Public", description = "Public endpoints (no authentication required)")
public class PublicController {

    @Operation(summary = "Health check", description = "Check if the API is running")
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "timestamp", LocalDateTime.now(),
            "service", "spring-security-jwt-demo"
        ));
    }

    @Operation(summary = "API info", description = "Get API version and information")
    @GetMapping("/info")
    public ResponseEntity<Map<String, String>> info() {
        return ResponseEntity.ok(Map.of(
            "name", "Spring Security JWT Demo API",
            "version", "1.0.0",
            "description", "REST API with JWT Authentication"
        ));
    }
}
