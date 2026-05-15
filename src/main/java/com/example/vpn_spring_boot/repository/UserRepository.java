package com.example.vpn_spring_boot.repository;

import com.example.vpn_spring_boot.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("SELECT COALESCE(MAX(u.vpnIpOctet), 1) FROM User u")
    int findMaxVpnIpOctet();

    java.util.List<User> findAllByPeerSyncedFalse();
}
