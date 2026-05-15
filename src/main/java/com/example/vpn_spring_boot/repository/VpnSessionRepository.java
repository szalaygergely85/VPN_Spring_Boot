package com.example.vpn_spring_boot.repository;

import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.model.VpnSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VpnSessionRepository extends JpaRepository<VpnSession, Long> {
    Optional<VpnSession> findTopByUserAndDisconnectedAtIsNullOrderByConnectedAtDesc(User user);
    List<VpnSession> findTop20ByOrderByConnectedAtDesc();
}
