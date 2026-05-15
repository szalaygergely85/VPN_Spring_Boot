package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.model.AuditLog;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.AuditLogRepository;
import com.example.vpn_spring_boot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class BandwidthScheduler {

    private static final Logger log = LoggerFactory.getLogger(BandwidthScheduler.class);
    private static final long ONLINE_THRESHOLD_SECONDS = 180;

    @Value("${traffic.server-monthly-bytes:21990232555520}") // 20 TB
    private long serverMonthlyBytes;

    private final WireGuardSshService wireGuardSshService;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;

    @Scheduled(fixedDelay = 300_000) // every 5 minutes
    public void syncBandwidth() {
        String dump = wireGuardSshService.showDump();
        if (dump == null || dump.isBlank()) return;

        Map<String, long[]> peerStats = parseDump(dump);
        if (peerStats.isEmpty()) return;

        List<User> users = userRepository.findAll();
        long nowEpoch = System.currentTimeMillis() / 1000;
        long serverTotalMonthly = 0;

        for (User user : users) {
            long[] stats = peerStats.get(user.getVpnPublicKey());
            if (stats == null) continue;

            long newRx = stats[0];
            long newTx = stats[1];
            long handshake = stats[2];

            // Compute delta — if counter went backwards, WireGuard restarted; treat new value as delta
            long deltaRx = newRx >= user.getLastPollRxBytes() ? newRx - user.getLastPollRxBytes() : newRx;
            long deltaTx = newTx >= user.getLastPollTxBytes() ? newTx - user.getLastPollTxBytes() : newTx;

            user.setRxBytes(newRx);
            user.setTxBytes(newTx);
            user.setLastPollRxBytes(newRx);
            user.setLastPollTxBytes(newTx);
            user.setMonthlyRxBytes(user.getMonthlyRxBytes() + deltaRx);
            user.setMonthlyTxBytes(user.getMonthlyTxBytes() + deltaTx);

            if (handshake > 0 && (nowEpoch - handshake) < ONLINE_THRESHOLD_SECONDS) {
                user.setLastSeen(LocalDateTime.now());
            }

            serverTotalMonthly += user.getMonthlyRxBytes() + user.getMonthlyTxBytes();

            // Suspend if over limit (limit > 0 means enforced)
            long used = user.getMonthlyRxBytes() + user.getMonthlyTxBytes();
            if (!user.isSuspended() && user.getBytesLimit() > 0 && used >= user.getBytesLimit()) {
                boolean removed = wireGuardSshService.removePeer(user.getVpnPublicKey());
                if (removed) {
                    user.setSuspended(true);
                    user.setPeerSynced(false);
                    auditLogRepository.save(AuditLog.of(
                        user.getEmail(), "BANDWIDTH_EXCEEDED", null,
                        String.format("Used %d MB of %d MB limit", used / (1024 * 1024), user.getBytesLimit() / (1024 * 1024))
                    ));
                    log.warn("User {} suspended — bandwidth limit exceeded ({} MB)", user.getEmail(), used / (1024 * 1024));
                }
            }
        }

        userRepository.saveAll(users);

        // Alert when server total exceeds 80% of monthly cap
        if (serverTotalMonthly > (serverMonthlyBytes * 0.8)) {
            log.warn("SERVER BANDWIDTH ALERT: monthly usage is {} GB / {} GB (>80%)",
                serverTotalMonthly / (1024L * 1024 * 1024),
                serverMonthlyBytes / (1024L * 1024 * 1024));
        }
    }

    // Returns map: publicKey -> [rxBytes, txBytes, lastHandshake]
    private Map<String, long[]> parseDump(String dump) {
        Map<String, long[]> map = new HashMap<>();
        String[] lines = dump.split("\n");
        for (int i = 1; i < lines.length; i++) {
            String[] cols = lines[i].trim().split("\t");
            if (cols.length < 7) continue;
            map.put(cols[0], new long[]{ parseLong(cols[5]), parseLong(cols[6]), parseLong(cols[4]) });
        }
        return map;
    }

    private long parseLong(String s) {
        try { return Long.parseLong(s.trim()); } catch (NumberFormatException e) { return 0; }
    }
}
