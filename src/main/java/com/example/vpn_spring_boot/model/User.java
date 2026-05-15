package com.example.vpn_spring_boot.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column
    private String vpnPrivateKey;

    @Column
    private String vpnPublicKey;

    @Column
    private String vpnAddress;

    @Column
    private int vpnIpOctet;

    @Column(nullable = false)
    private boolean peerSynced = false;

    @Column(nullable = false)
    private boolean suspended = false;

    @Column(nullable = false)
    private boolean admin = false;

    // Raw live values from the last wg show dump (for admin display + delta tracking)
    @Column(nullable = false)
    private long rxBytes = 0;

    @Column(nullable = false)
    private long txBytes = 0;

    // Previous poll raw values — used to compute the delta each cycle
    @Column(nullable = false)
    private long lastPollRxBytes = 0;

    @Column(nullable = false)
    private long lastPollTxBytes = 0;

    // Monthly accumulated totals — reset on 1st of each month
    @Column(nullable = false)
    private long monthlyRxBytes = 0;

    @Column(nullable = false)
    private long monthlyTxBytes = 0;

    // Per-user monthly cap in bytes; set from config at registration, adjustable per user
    @Column(nullable = false)
    private long bytesLimit = 0;

    @Column
    private LocalDateTime lastSeen;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return admin ? List.of(new SimpleGrantedAuthority("ROLE_ADMIN")) : List.of();
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }
}
