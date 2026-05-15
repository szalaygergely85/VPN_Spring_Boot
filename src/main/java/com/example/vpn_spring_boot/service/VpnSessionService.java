package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.model.AuditLog;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.model.VpnSession;
import com.example.vpn_spring_boot.repository.AuditLogRepository;
import com.example.vpn_spring_boot.repository.VpnSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class VpnSessionService {

    private final VpnSessionRepository vpnSessionRepository;
    private final AuditLogRepository auditLogRepository;

    @Transactional
    public void connect(User user, String clientIp) {
        // Close any dangling open session (e.g. app crash)
        vpnSessionRepository
            .findTopByUserAndDisconnectedAtIsNullOrderByConnectedAtDesc(user)
            .ifPresent(s -> {
                s.setDisconnectedAt(LocalDateTime.now());
                vpnSessionRepository.save(s);
            });

        VpnSession session = new VpnSession();
        session.setUser(user);
        session.setClientIp(clientIp);
        vpnSessionRepository.save(session);

        auditLogRepository.save(AuditLog.of(user.getEmail(), "VPN_CONNECT", clientIp, null));
    }

    @Transactional
    public void disconnect(User user, String clientIp) {
        vpnSessionRepository
            .findTopByUserAndDisconnectedAtIsNullOrderByConnectedAtDesc(user)
            .ifPresent(s -> {
                s.setDisconnectedAt(LocalDateTime.now());
                vpnSessionRepository.save(s);
            });

        auditLogRepository.save(AuditLog.of(user.getEmail(), "VPN_DISCONNECT", clientIp, null));
    }

    public void audit(String email, String action, String ipAddress, String detail) {
        auditLogRepository.save(AuditLog.of(email, action, ipAddress, detail));
    }
}
