package com.example.vpn_spring_boot.controller;

import com.example.vpn_spring_boot.dto.AdminStatusResponse;
import com.example.vpn_spring_boot.dto.AuditLogDto;
import com.example.vpn_spring_boot.dto.PeerStatusDto;
import com.example.vpn_spring_boot.model.AuditLog;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.AuditLogRepository;
import com.example.vpn_spring_boot.repository.UserRepository;
import com.example.vpn_spring_boot.service.WireGuardSshService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private static final long ONLINE_THRESHOLD_SECONDS = 180;

    private final WireGuardSshService wireGuardSshService;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;

    @GetMapping("/status")
    public AdminStatusResponse status() {
        // Parse live wg show dump
        Map<String, String[]> peerDump = parseDump(wireGuardSshService.showDump());

        List<User> users = userRepository.findAll();
        long nowEpoch = System.currentTimeMillis() / 1000;

        List<PeerStatusDto> peers = users.stream()
            .filter(u -> u.getVpnPublicKey() != null)
            .map(u -> {
                String[] cols = peerDump.get(u.getVpnPublicKey());
                String endpoint      = cols != null ? cols[0] : "(none)";
                long   lastHandshake = cols != null ? parseLong(cols[2]) : 0;
                long   rx            = cols != null ? parseLong(cols[3]) : u.getRxBytes();
                long   tx            = cols != null ? parseLong(cols[4]) : u.getTxBytes();
                boolean online       = lastHandshake > 0 && (nowEpoch - lastHandshake) < ONLINE_THRESHOLD_SECONDS;
                return new PeerStatusDto(u.getEmail(), u.getVpnAddress(), endpoint, lastHandshake, rx, tx, online);
            })
            .toList();

        int onlineCount = (int) peers.stream().filter(PeerStatusDto::online).count();

        List<AuditLogDto> auditLog = auditLogRepository.findTop50ByOrderByCreatedAtDesc()
            .stream()
            .map(a -> new AuditLogDto(a.getEmail(), a.getAction(), a.getIpAddress(), a.getDetail(), a.getCreatedAt()))
            .toList();

        return new AdminStatusResponse(users.size(), onlineCount, peers, auditLog);
    }

    // Returns map: publicKey -> [endpoint, allowedIps, lastHandshake, rxBytes, txBytes]
    private Map<String, String[]> parseDump(String dump) {
        Map<String, String[]> map = new HashMap<>();
        if (dump == null || dump.isBlank()) return map;
        String[] lines = dump.split("\n");
        for (int i = 1; i < lines.length; i++) {
            String[] cols = lines[i].trim().split("\t");
            if (cols.length < 7) continue;
            // cols: pubkey, preshared, endpoint, allowed-ips, last-handshake, rx, tx, keepalive
            map.put(cols[0], new String[]{ cols[2], cols[3], cols[4], cols[5], cols[6] });
        }
        return map;
    }

    private long parseLong(String s) {
        try { return Long.parseLong(s.trim()); } catch (NumberFormatException e) { return 0; }
    }
}
