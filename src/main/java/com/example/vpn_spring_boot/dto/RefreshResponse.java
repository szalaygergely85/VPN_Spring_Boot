package com.example.vpn_spring_boot.dto;

public record RefreshResponse(String accessToken, String refreshToken, long tokenExpiresAt) {}
