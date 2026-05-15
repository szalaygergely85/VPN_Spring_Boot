package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.model.AuditLog;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.AuditLogRepository;
import com.example.vpn_spring_boot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class MonthlyResetScheduler {

    private static final Logger log = LoggerFactory.getLogger(MonthlyResetScheduler.class);

    private final UserRepository userRepository;
    private final WireGuardSshService wireGuardSshService;
    private final AuditLogRepository auditLogRepository;

    // Runs at midnight on the 1st of every month
    @Scheduled(cron = "0 0 0 1 * *")
    public void resetMonthlyBandwidth() {
        log.info("Monthly bandwidth reset started");
        List<User> users = userRepository.findAll();
        int restored = 0;

        for (User user : users) {
            user.setMonthlyRxBytes(0);
            user.setMonthlyTxBytes(0);
            user.setLastPollRxBytes(0);
            user.setLastPollTxBytes(0);

            // Restore suspended users — re-add their WireGuard peer
            if (user.isSuspended()) {
                boolean ok = wireGuardSshService.addPeer(user.getVpnPublicKey(), user.getVpnAddress());
                if (ok) {
                    user.setSuspended(false);
                    user.setPeerSynced(true);
                    auditLogRepository.save(AuditLog.of(user.getEmail(), "BANDWIDTH_RESET", null, "Monthly quota reset"));
                    restored++;
                }
            }
        }

        userRepository.saveAll(users);
        log.info("Monthly reset complete — {} user(s) restored, {} total users reset", restored, users.size());
    }
}
