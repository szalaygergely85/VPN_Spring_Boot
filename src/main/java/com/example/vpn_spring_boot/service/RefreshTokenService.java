package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.model.RefreshToken;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration-days:30}")
    private int refreshExpirationDays;

    @Transactional
    public RefreshToken create(User user) {
        RefreshToken token = new RefreshToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUser(user);
        token.setExpiresAt(LocalDateTime.now().plusDays(refreshExpirationDays));
        return refreshTokenRepository.save(token);
    }

    // Validates and rotates: revokes the old token, issues a new one
    @Transactional
    public RefreshToken rotate(String tokenValue) {
        RefreshToken existing = refreshTokenRepository.findByToken(tokenValue)
            .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        if (existing.isRevoked()) {
            // Token reuse detected — revoke all tokens for this user
            refreshTokenRepository.revokeAllByUser(existing.getUser());
            throw new IllegalArgumentException("Refresh token already used — all sessions revoked");
        }
        if (existing.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Refresh token expired");
        }

        existing.setRevoked(true);
        refreshTokenRepository.save(existing);

        return create(existing.getUser());
    }

    @Transactional
    public void revokeAll(User user) {
        refreshTokenRepository.revokeAllByUser(user);
    }
}
