package com.example.security.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory token revocation list.
 *
 * Stores revoked JWTs until they expire.
 * For production, replace with a persistent/shared store.
 */
@Service
public class TokenBlacklistService {

    private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

    public void revoke(String token, Date expiresAt) {
        if (token == null || token.isBlank()) {
            return;
        }
        Instant expiry = expiresAt == null ? Instant.EPOCH : expiresAt.toInstant();
        revokedTokens.put(token, expiry);
    }

    public boolean isTokenRevoked(String token) {
        if (token == null) {
            return false;
        }
        Instant expiry = revokedTokens.get(token);
        if (expiry == null) {
            return false;
        }
        if (expiry.isBefore(Instant.now())) {
            revokedTokens.remove(token);
            return false;
        }
        return true;
    }
}
