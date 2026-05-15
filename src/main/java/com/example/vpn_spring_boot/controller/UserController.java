package com.example.vpn_spring_boot.controller;

import com.example.vpn_spring_boot.model.AuditLog;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.AuditLogRepository;
import com.example.vpn_spring_boot.repository.RefreshTokenRepository;
import com.example.vpn_spring_boot.repository.UserRepository;
import com.example.vpn_spring_boot.repository.VpnSessionRepository;
import com.example.vpn_spring_boot.service.WireGuardSshService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VpnSessionRepository vpnSessionRepository;
    private final AuditLogRepository auditLogRepository;
    private final WireGuardSshService wireGuardSshService;

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getMe(@AuthenticationPrincipal User user) {
        long used = user.getMonthlyRxBytes() + user.getMonthlyTxBytes();
        return ResponseEntity.ok(Map.of(
            "monthlyUsedBytes", used,
            "monthlyLimitBytes", user.getBytesLimit(),
            "suspended", user.isSuspended()
        ));
    }

    @DeleteMapping("/me")
    @Transactional
    public ResponseEntity<Void> deleteAccount(@AuthenticationPrincipal User user,
                                              HttpServletRequest request) {
        wireGuardSshService.removePeer(user.getVpnPublicKey());
        vpnSessionRepository.deleteAllByUser(user);
        refreshTokenRepository.deleteAllByUser(user);
        auditLogRepository.save(AuditLog.of(user.getEmail(), "ACCOUNT_DELETED", resolveIp(request), null));
        userRepository.delete(user);
        return ResponseEntity.noContent().build();
    }

    private String resolveIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) return forwarded.split(",")[0].trim();
        return request.getRemoteAddr();
    }
}
