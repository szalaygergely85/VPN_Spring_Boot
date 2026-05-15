package com.example.vpn_spring_boot.dto;

import java.util.List;

public record AdminStatusResponse(
    int totalUsers,
    int onlinePeers,
    List<PeerStatusDto> peers,
    List<AuditLogDto> recentAuditLog
) {}
