package com.example.vpn_spring_boot.dto;

public record RegisterResponse(
    String id,
    String email,
    String vpnPrivateKey,
    String vpnAddress,
    String token,
    String refreshToken,
    long tokenExpiresAt,
    WireGuardServerConfig serverConfig
) {}
