package com.example.vpn_spring_boot.dto;

public record WireGuardServerConfig(
    String host,
    int port,
    String publicKey,
    String dns,
    String allowedIPs,
    int persistentKeepalive
) {}
