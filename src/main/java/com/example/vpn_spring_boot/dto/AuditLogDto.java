package com.example.vpn_spring_boot.dto;

import java.time.LocalDateTime;

public record AuditLogDto(
    String email,
    String action,
    String ipAddress,
    String detail,
    LocalDateTime createdAt
) {}
