package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class PeerSyncScheduler {

    private static final Logger log = LoggerFactory.getLogger(PeerSyncScheduler.class);

    private final UserRepository userRepository;
    private final WireGuardSshService wireGuardSshService;

    // Runs every 60 seconds, retries any users whose peer wasn't added
    @Scheduled(fixedDelay = 60_000)
    public void syncPendingPeers() {
        List<User> pending = userRepository.findAllByPeerSyncedFalse();
        if (pending.isEmpty()) return;

        log.info("Retrying WireGuard peer sync for {} user(s)", pending.size());
        for (User user : pending) {
            boolean ok = wireGuardSshService.addPeer(user.getVpnPublicKey(), user.getVpnAddress());
            if (ok) {
                user.setPeerSynced(true);
                userRepository.save(user);
                log.info("Peer synced for user {}", user.getEmail());
            }
        }
    }
}
