package com.example.vpn_spring_boot.dto;

public record PeerStatusDto(
    String email,
    String vpnAddress,
    String endpoint,
    long lastHandshakeEpoch,
    long rxBytes,
    long txBytes,
    boolean online
) {}
