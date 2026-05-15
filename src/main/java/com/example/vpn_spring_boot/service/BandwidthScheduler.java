package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    // A peer is considered online if its last handshake was within 3 minutes
    private static final long ONLINE_THRESHOLD_SECONDS = 180;

    private final WireGuardSshService wireGuardSshService;
    private final UserRepository userRepository;

    @Scheduled(fixedDelay = 300_000) // every 5 minutes
    public void syncBandwidth() {
        String dump = wireGuardSshService.showDump();
        if (dump.isBlank()) return;

        // Build a map: publicKey -> [rxBytes, txBytes, lastHandshake]
        Map<String, long[]> peerStats = new HashMap<>();
        String[] lines = dump.split("\n");
        for (int i = 1; i < lines.length; i++) { // skip interface line
            String[] cols = lines[i].trim().split("\t");
            if (cols.length < 7) continue;
            String pubKey    = cols[0];
            long   rx        = parseLong(cols[5]);
            long   tx        = parseLong(cols[6]);
            long   handshake = parseLong(cols[4]);
            peerStats.put(pubKey, new long[]{ rx, tx, handshake });
        }

        if (peerStats.isEmpty()) return;

        List<User> users = userRepository.findAll();
        long now = System.currentTimeMillis() / 1000;

        for (User user : users) {
            long[] stats = peerStats.get(user.getVpnPublicKey());
            if (stats == null) continue;
            user.setRxBytes(stats[0]);
            user.setTxBytes(stats[1]);
            if (stats[2] > 0 && (now - stats[2]) < ONLINE_THRESHOLD_SECONDS) {
                user.setLastSeen(LocalDateTime.now());
            }
        }

        userRepository.saveAll(users);
        log.debug("Bandwidth stats updated for {} users", users.size());
    }

    // Parse wg show dump values — "(none)" maps to 0
    private long parseLong(String s) {
        try { return Long.parseLong(s.trim()); } catch (NumberFormatException e) { return 0; }
    }
}
